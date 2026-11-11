//! Property columns and filters: every indexed evaluation must equal the
//! reference per-node evaluation over the stored JSON, on random data.

use ch_model::{flags, NodeKind};
use ch_store::{ColType, Edge, Filter, Graph, GraphParts, Op, RoaringBitmap};
use serde_json::{json, Value};
use std::path::PathBuf;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

const DOMAINS: &[&str] = &["corp.local", "CORP.LOCAL", "Dev.Local", "eu.corp.local", "", "123", "x"];
const OSES: &[&str] = &["Windows 10", "WINDOWS 10", "Windows Server 2019", "Ubuntu", "windows 11"];
const WORDS: &[&str] = &["svc", "Admin", "backup", "SQL", "web", "test", "ü-ñ", "42", "x"];
const KINDS: &[NodeKind] = &[NodeKind::User, NodeKind::Computer, NodeKind::Group, NodeKind::Domain, NodeKind::AzUser];

fn word_string(r: &mut Rng, max: usize) -> String {
    let n = 1 + r.below(max);
    (0..n).map(|_| r.pick(WORDS).to_string()).collect::<Vec<_>>().join(" ")
}

fn random_props(r: &mut Rng, i: usize) -> Option<String> {
    match r.below(40) {
        0 => return None,
        1 => return Some("{\"broken\": 1,".into()),
        2 => return Some("[1,2]".into()),
        3 => return Some("{\"domain\":\"tail.local\"} trailing".into()),
        _ => {}
    }
    let mut items: Vec<(String, Value)> = Vec::new();
    let mut add = |r: &mut Rng, p: f64, k: &str, v: Value| {
        if r.chance(p) {
            items.push((k.to_string(), v));
        }
    };
    let dom = if r.chance(0.1) { Value::Null } else { json!(r.pick(DOMAINS)) };
    add(r, 0.8, "domain", dom);
    let os = json!(r.pick(OSES));
    add(r, 0.4, "operatingsystem", os);
    // High cardinality (beyond the equality-index threshold).
    let desc = if r.chance(0.05) { Value::Null } else { json!(format!("{} #{i}", word_string(r, 3))) };
    add(r, 0.7, "description", desc);
    let sam = json!(format!("{}{}", r.pick(&["user", "User", "SVC_", "adm"]), r.below(9000)));
    add(r, 0.9, "samaccountname", sam);
    let ll = match r.below(4) {
        0 => json!(-1),
        1 => json!(0),
        2 => json!(1_600_000_000 + r.below(100_000_000) as i64),
        _ => json!(r.below(100) as i64),
    };
    add(r, 0.7, "lastlogon", ll);
    let score = if r.chance(0.5) { json!(r.below(10) as f64 / 4.0) } else { json!(r.below(10) as i64) };
    add(r, 0.5, "score", score);
    let big = json!(u64::MAX - r.below(3) as u64);
    add(r, 0.05, "bignum", big);
    let b = json!(r.chance(0.5));
    add(r, 0.6, "sensitive", b);
    let mixed = match r.below(4) {
        0 => json!("12"),
        1 => json!(12),
        2 => json!(true),
        _ => json!(word_string(r, 2)),
    };
    add(r, 0.5, "mixed", mixed);
    let spns: Vec<Value> = (0..r.below(3)).map(|k| json!(format!("HTTP/web{k}.{}", r.pick(DOMAINS)))).collect();
    add(r, 0.5, "serviceprincipalnames", Value::Array(spns));
    add(r, 0.1, "obj", json!({"a": 1}));
    let ns = json!(*r.pick(&["12", " 7", "7", "abc", "1e3", "-4.5", "", "ABC"]));
    add(r, 0.6, "numstr", ns);
    add(r, 0.3, "allnull", Value::Null);
    let en = if r.chance(0.1) { Value::Null } else { json!(r.chance(0.7)) };
    add(r, 0.6, "enabled", en);
    // Duplicate key differing in case: the first occurrence wins.
    if r.chance(0.05) {
        let at = r.below(items.len() + 1);
        items.insert(at, ("DOMAIN".into(), json!("dup.local")));
    }
    if r.chance(0.03) {
        items.push(("Domain".into(), json!(7)));
    }
    let body: Vec<String> = items.iter().map(|(k, v)| format!("{}:{}", json!(k), v)).collect();
    Some(format!("{{{}}}", body.join(",")))
}

fn random_graph(seed: u64, n: usize) -> Graph {
    let mut r = Rng(seed);
    let mut names = Vec::new();
    let mut oids = Vec::new();
    let mut kinds = Vec::new();
    let mut fl = Vec::new();
    let mut props = Vec::new();
    for i in 0..n {
        kinds.push(*r.pick(KINDS) as u8);
        let mut f = 0;
        for bit in [flags::ENABLED, flags::TIER0, flags::OWNED, flags::HAS_SPN, flags::UNCONSTRAINED_DELEGATION] {
            if r.chance(0.3) {
                f |= bit;
            }
        }
        fl.push(f);
        names.push(match r.below(12) {
            0 => None,
            1 => Some(format!("{}{i}@Corp.Local", r.pick(&["user", "Svc_"]))),
            _ => Some(format!("{}{i}@{}", r.pick(&["USER", "SVC_", "ADMIN", "WS", "SQL"]), r.pick(&["CORP.LOCAL", "DEV.LOCAL"]))),
        });
        oids.push(if r.chance(0.02) { format!("s-1-5-21-{i}") } else { format!("S-1-5-21-{i}") });
        props.push(random_props(&mut r, i));
    }
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let edges = (1..n as u32).map(|i| Edge::new(i, i / 2, 0)).collect();
    Graph::build(GraphParts {
        kinds,
        flags: fl,
        names,
        oids,
        props,
        edge_chunks: vec![edges],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap()
    .0
}

const KEYS: &[&str] = &[
    "name", "objectid", "kind", "id", "enabled", "owned", "tier0", "hasspn", "domain", "DoMaIn", "operatingsystem",
    "description", "samaccountname", "lastlogon", "score", "bignum", "sensitive", "mixed", "serviceprincipalnames",
    "obj", "numstr", "allnull", "missing",
];
const OPS: &[Op] = &[Op::Eq, Op::Ne, Op::Lt, Op::Le, Op::Gt, Op::Ge, Op::StartsWith, Op::EndsWith, Op::Contains, Op::In];

fn random_value(r: &mut Rng, g: &Graph) -> Value {
    match r.below(12) {
        0 => json!(r.pick(DOMAINS)),
        1 => json!(r.pick(OSES)),
        2 => json!(r.pick(WORDS)),
        3 => json!(r.below(200) as i64 - 50),
        4 => json!(1_600_000_000 + r.below(100_000_000) as i64),
        5 => json!(r.below(10) as f64 / 4.0),
        6 => json!(r.chance(0.5)),
        7 => Value::Null,
        8 => {
            // A real name / object id, possibly re-cased or truncated.
            let id = r.below(g.node_count()) as u32;
            let s = if r.chance(0.5) { g.name(id).to_string() } else { g.oid(id).to_string() };
            let s = if r.chance(0.5) { s.to_ascii_lowercase() } else { s };
            let cut = r.below(s.len() + 1);
            json!(if r.chance(0.5) { s[..cut].to_string() } else { s })
        }
        9 => json!(*r.pick(&["12", "7", "1e3", "ABC", "user1", "User", "svc_", "", "HTTP/", "local"])),
        10 => json!(*r.pick(&["User", "computer", "GROUP", "AZUser", "Nope"])),
        _ => {
            let k = 1 + r.below(3);
            Value::Array((0..k).map(|_| random_value(r, g)).filter(|v| !v.is_array()).collect())
        }
    }
}

fn random_filter(r: &mut Rng, g: &Graph, depth: u32) -> Filter {
    let leaf = depth == 0 || r.chance(0.4);
    if !leaf {
        let k = 1 + r.below(3);
        let kids: Vec<Filter> = (0..k).map(|_| random_filter(r, g, depth - 1)).collect();
        return match r.below(3) {
            0 => Filter::And(kids),
            1 => Filter::Or(kids),
            _ => Filter::not(kids.into_iter().next().unwrap()),
        };
    }
    let key = r.pick(KEYS).to_string();
    match r.below(10) {
        0 => Filter::Kind((0..1 + r.below(2)).map(|_| *r.pick(KINDS)).collect()),
        1 => Filter::IsNull { key, null: r.chance(0.5) },
        2 => Filter::Truthy(key),
        3 if r.chance(0.2) => Filter::Const(r.chance(0.5)),
        _ => Filter::Cmp { key, op: *r.pick(OPS), value: random_value(r, g) },
    }
}

fn check_one(g: &Graph, f: &Filter, cand: &RoaringBitmap) -> bool {
    let fast = g.filter(f);
    let slow = g.filter_scan(f);
    assert_eq!(fast, slow, "{}", serde_json::to_string(f).unwrap());
    assert_eq!(g.filter_within(f, cand), &slow & cand, "within: {}", serde_json::to_string(f).unwrap());
    !slow.is_empty() && slow.len() < g.node_count() as u64
}

fn check_random(g: &Graph, seed: u64, rounds: usize, min_nontrivial: usize) {
    let mut r = Rng(seed);
    let mut nontrivial = 0;
    for _ in 0..rounds {
        let f = random_filter(&mut r, g, 3);
        let cand: RoaringBitmap = (0..g.node_count() as u32).filter(|_| r.chance(0.1)).collect();
        nontrivial += check_one(g, &f, &cand) as usize;
    }
    assert!(nontrivial >= min_nontrivial, "only {nontrivial} of {rounds} filters had a non-trivial result");
}

/// Every key with every operator (and null / truthiness), as single leaves.
fn check_leaves(g: &Graph, seed: u64, values_per_op: usize) {
    let mut r = Rng(seed);
    let cand: RoaringBitmap = (0..g.node_count() as u32).filter(|_| r.chance(0.05)).collect();
    for key in KEYS {
        check_one(g, &Filter::is_null(*key), &cand);
        check_one(g, &Filter::IsNull { key: key.to_string(), null: false }, &cand);
        check_one(g, &Filter::truthy(*key), &cand);
        for &op in OPS {
            for _ in 0..values_per_op {
                check_one(g, &Filter::cmp(*key, op, random_value(&mut r, g)), &cand);
                // A value this key actually has somewhere, possibly re-cased
                // or cut to a prefix / suffix.
                let id = r.below(g.node_count()) as u32;
                let v = match g.node_value(id, key) {
                    ch_store::Val::Str(s) => {
                        let s = match r.below(3) {
                            0 => s.to_ascii_lowercase(),
                            1 => s.to_ascii_uppercase(),
                            _ => s,
                        };
                        let cut = r.below(s.len() + 1);
                        match r.below(3) {
                            0 if s.is_char_boundary(cut) => json!(s[..cut]),
                            1 if s.is_char_boundary(cut) => json!(s[cut..]),
                            _ => json!(s),
                        }
                    }
                    ch_store::Val::Num(x) => json!(x),
                    ch_store::Val::Bool(b) => json!(b),
                    ch_store::Val::Null => Value::Null,
                    ch_store::Val::List(l) => match l.first() {
                        Some(ch_store::Val::Str(s)) => json!(s),
                        _ => json!([]),
                    },
                };
                check_one(g, &Filter::cmp(*key, op, v), &cand);
            }
        }
    }
}

#[test]
fn every_leaf_matches_reference() {
    let g = random_graph(21, 9000);
    check_leaves(&g, 5, scale(12));
}

/// Fewer random rounds in unoptimised builds (`cargo test --release` runs all).
fn scale(n: usize) -> usize {
    if cfg!(debug_assertions) {
        n.div_ceil(4)
    } else {
        n
    }
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn columns_have_expected_types() {
    let g = random_graph(1, 9000);
    let info = g.columns().info();
    let ty = |k: &str| info.iter().find(|c| c.key == k).map(|c| c.ty);
    assert_eq!(ty("domain"), Some(ColType::Raw), "domain has a duplicate numeric 'Domain'");
    assert_eq!(ty("operatingsystem"), Some(ColType::Str));
    assert_eq!(ty("description"), Some(ColType::Str));
    assert_eq!(ty("lastlogon"), Some(ColType::Int));
    assert_eq!(ty("score"), Some(ColType::Float));
    assert_eq!(ty("bignum"), Some(ColType::Float));
    assert_eq!(ty("sensitive"), Some(ColType::Bool));
    assert_eq!(ty("mixed"), Some(ColType::Raw));
    assert_eq!(ty("serviceprincipalnames"), Some(ColType::Raw));
    assert_eq!(ty("allnull"), Some(ColType::Null));
    let os = info.iter().find(|c| c.key == "operatingsystem").unwrap();
    assert!(os.eq_index);
    let desc = info.iter().find(|c| c.key == "description").unwrap();
    assert!(!desc.eq_index, "description is high-cardinality");
}

#[test]
fn random_filters_match_reference_in_memory() {
    let g = random_graph(7, 6000);
    check_random(&g, 100, scale(600), scale(150));
}

#[test]
fn random_filters_match_reference_mapped_multi_block() {
    // > 2^16 nodes: several scan blocks, mmap-backed columns.
    let g = random_graph(8, 140_000);
    let dir = tmp("mapped");
    g.write(&dir).unwrap();
    drop(g);
    let g = Graph::open(&dir).unwrap();
    assert!(g.columns().origin.loaded);
    check_random(&g, 200, scale(60), scale(10));
    check_leaves(&g, 201, 1);
    drop(g);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn string_column_with_clean_domain() {
    // Without the duplicate-key noise `domain` is a dictionary column.
    let n = 3000;
    let mut r = Rng(3);
    let props: Vec<Option<String>> = (0..n).map(|_| Some(json!({"domain": r.pick(DOMAINS), "n": r.below(5)}).to_string())).collect();
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let (g, _) = Graph::build(GraphParts {
        kinds: vec![NodeKind::User as u8; n],
        flags: vec![0; n],
        names: (0..n).map(|i| Some(format!("U{i}"))).collect(),
        oids: (0..n).map(|i| format!("S-{i}")).collect(),
        props,
        edge_chunks: vec![],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap();
    assert_eq!(g.columns().info().iter().find(|c| c.key == "domain").unwrap().ty, ColType::Str);
    let f = Filter::eq("domain", "CORP.local");
    let hits = g.filter(&f);
    assert_eq!(hits, g.filter_scan(&f));
    // "corp.local" and "CORP.LOCAL" are both values; equality ignores case.
    assert!(hits.iter().any(|id| g.props(id).contains("corp.local")) && hits.iter().any(|id| g.props(id).contains("CORP.LOCAL")));
    check_random(&g, 300, scale(300), 1);
}

#[test]
fn old_format_graph_builds_columns_lazily_and_persists() {
    let g = random_graph(11, 5000);
    let dir = tmp("oldfmt");
    g.write(&dir).unwrap();
    let expected = g.filter_scan(&Filter::And(vec![Filter::kind(NodeKind::User), Filter::eq("operatingsystem", "windows 10")]));
    drop(g);
    // Turn it into a format-2 directory: no column files, old version.
    std::fs::remove_file(dir.join("columns.json")).unwrap();
    std::fs::remove_file(dir.join("columns.bin")).unwrap();
    let meta = std::fs::read_to_string(dir.join("meta.json")).unwrap();
    let meta = meta.replace("\"format_version\": 3", "\"format_version\": 2");
    assert!(meta.contains("\"format_version\": 2"));
    std::fs::write(dir.join("meta.json"), meta).unwrap();

    let g = Graph::open(&dir).unwrap();
    assert!(g.columns_ready().is_none(), "columns are lazy");
    let f = Filter::And(vec![Filter::kind(NodeKind::User), Filter::eq("operatingsystem", "windows 10")]);
    assert_eq!(g.filter(&f), expected);
    let origin = g.columns().origin.clone();
    assert!(!origin.loaded && origin.persist_error.is_none(), "{origin:?}");
    assert!(dir.join("columns.json").exists() && dir.join("columns.bin").exists());
    drop(g);

    let g = Graph::open(&dir).unwrap();
    assert!(g.columns().origin.loaded, "second open loads persisted columns");
    assert_eq!(g.filter(&f), expected);
    drop(g);

    // A stale or corrupt manifest is rebuilt rather than trusted.
    std::fs::write(dir.join("columns.json"), "{\"version\": 999}").unwrap();
    let g = Graph::open(&dir).unwrap();
    assert_eq!(g.filter(&f), expected);
    assert!(!g.columns().origin.loaded);
    drop(g);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn flag_changes_invalidate_flag_bitmaps() {
    let mut g = random_graph(5, 2000);
    let f = Filter::eq("owned", true);
    let before = g.filter(&f);
    let id = (0..2000).find(|&i| !before.contains(i)).unwrap();
    g.set_flag(id, flags::OWNED, true);
    let after = g.filter(&f);
    assert!(after.contains(id));
    assert_eq!(after, g.filter_scan(&f));
}

#[test]
fn search_ranks_exact_prefix_then_substring() {
    let n = 8;
    let names = ["ALICE@CORP", "ALICE.ADMIN@CORP", "BOB@CORP", "MALICE@CORP", "AL@CORP", "XALICEX@CORP", "", "ALICIA@CORP"];
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let (g, _) = Graph::build(GraphParts {
        kinds: vec![NodeKind::User as u8; n],
        flags: vec![0; n],
        names: names.iter().map(|s| (!s.is_empty()).then(|| s.to_string())).collect(),
        oids: (0..n).map(|i| format!("S-1-{i}ALICE")).collect(),
        props: vec![None; n],
        edge_chunks: vec![],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap();
    // Before columns exist: prefix only.
    assert_eq!(g.search("alice", None, 10), vec![0, 1]);
    let _ = g.columns();
    let got: Vec<&str> = g.search("alice", None, 10).iter().map(|&i| g.name(i)).collect();
    assert_eq!(got, vec!["ALICE@CORP", "ALICE.ADMIN@CORP", "S-1-6ALICE", "MALICE@CORP", "XALICEX@CORP"]);
    assert_eq!(g.search("alice", Some(NodeKind::Computer), 10), Vec::<u32>::new());
    assert_eq!(g.search("ALICE@CORP", None, 1), vec![0]);
}

/// Edge cases aligned with CHQL's evaluator so CHQL can push them down:
/// `<> null` matches nothing, `null IN [null]` is false, string order breaks
/// case-folded ties by bytes, object-id equality returns duplicates and works
/// for the empty id.
#[test]
fn chql_aligned_edge_cases() {
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let props = [r#"{"d":"a","x":null}"#, r#"{"d":"A"}"#, r#"{"d":"b"}"#, r#"{}"#];
    let (g, _) = Graph::build(GraphParts {
        kinds: vec![NodeKind::User as u8; 4],
        flags: vec![0; 4],
        names: (0..4).map(|i| Some(format!("N{i}"))).collect(),
        oids: vec!["S-1".into(), "S-1".into(), "".into(), "S-2".into()],
        props: props.iter().map(|p| Some(p.to_string())).collect(),
        edge_chunks: vec![Vec::<Edge>::new()],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap();
    g.columns();
    let ids = |f: Filter| -> Vec<u32> {
        let r: Vec<u32> = g.filter(&f).iter().collect();
        let all = RoaringBitmap::from_iter(0..4u32);
        assert_eq!(r, g.filter_within(&f, &all).iter().collect::<Vec<_>>());
        assert_eq!(r, (0..4).filter(|&i| f.matches(&g, i)).collect::<Vec<_>>(), "{f:?}");
        r
    };
    assert_eq!(ids(Filter::cmp("d", Op::Ne, Value::Null)), Vec::<u32>::new());
    assert_eq!(ids(Filter::cmp("x", Op::In, json!([null]))), Vec::<u32>::new());
    assert_eq!(ids(Filter::cmp("d", Op::In, json!([null, "b"]))), vec![2]);
    assert_eq!(ids(Filter::cmp("d", Op::Gt, "A")), vec![0, 2]);
    assert_eq!(ids(Filter::cmp("d", Op::Le, "A")), vec![1]);
    assert_eq!(ids(Filter::cmp("d", Op::Lt, "a")), vec![1]);
    assert_eq!(ids(Filter::eq("objectid", "s-1")), vec![0, 1]);
    assert_eq!(ids(Filter::eq("objectid", "")), vec![2]);
    assert_eq!(ids(Filter::cmp("objectid", Op::In, json!(["S-1", "S-2"]))), vec![0, 1, 3]);
}

/// Prefix matches must be ranked shortest-first over the whole prefix range,
/// not just over its first entries in name order: "USER1@…" sorts after
/// "USER10000@…" because '@' > '9'.
#[test]
fn search_prefix_ranks_shortest_over_whole_range() {
    let n = 20_000;
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let (g, _) = Graph::build(GraphParts {
        kinds: vec![NodeKind::User as u8; n],
        flags: vec![0; n],
        names: (0..n).map(|i| Some(format!("USER{i}@CORP"))).collect(),
        oids: (0..n).map(|i| format!("S-1-5-21-9-{i}")).collect(),
        props: vec![None; n],
        edge_chunks: vec![],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap();
    let names = |ids: Vec<u32>| ids.iter().map(|&i| g.name(i).to_string()).collect::<Vec<_>>();
    let want = ["USER1@CORP", "USER10@CORP", "USER11@CORP", "USER12@CORP", "USER13@CORP"];
    // Without columns (prefix index only) and with columns.
    assert_eq!(names(g.search("user1", None, 5)), want);
    let _ = g.columns();
    assert_eq!(names(g.search("user1", None, 5)), want);
    assert_eq!(names(g.search("user12", None, 3)), ["USER12@CORP", "USER120@CORP", "USER121@CORP"]);
    // An exact match comes first even when its name is not the shortest hit.
    assert_eq!(names(g.search("S-1-5-21-9-19999", None, 2)), ["USER19999@CORP"]);
    // Substring hits follow the prefix hits, shortest first.
    assert_eq!(names(g.search("9999", None, 3)), ["USER9999@CORP", "USER19999@CORP"]);
}
