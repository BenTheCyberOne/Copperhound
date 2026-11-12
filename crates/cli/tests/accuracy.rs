//! Accuracy golden test: catches unintended changes to what CopperHound computes.
//!
//! For fixed inputs (a fixed-seed synthetic dataset and the committed CORP
//! fixtures) it records, as small order-independent hashes:
//!
//! * the node set per kind (object id, name, flags) and the edge set per edge
//!   kind (source and target object ids) after ingest and post-processing;
//! * Tier Zero exposure (counts per kind, exposed principals with their
//!   distance, choke points) with unified and per-realm Tier Zero;
//! * the remediation plan and the findings catalog;
//! * every prebuilt CHQL query, a few ad-hoc queries, node filters and search.
//!
//! Ingest numbers nodes by object id (and collector-specific edge kinds by
//! name), so the graph — and every analysis tie-break and floating-point sum
//! over it — is the same run to run and for any thread count; the analysis
//! runs on the ingested graph as is. `tests/determinism.rs` checks the
//! numbering itself across thread counts, batch sizes and input orders.
//!
//! A mismatch means behaviour changed. If the change is intended, regenerate
//! the golden file deliberately and review its diff:
//!
//! ```text
//! COPPERHOUND_UPDATE_GOLDEN=1 cargo test --release -p copperhound --test accuracy
//! ```
//!
//! `COPPERHOUND_ACCURACY_LARGE=1` adds a 100k-user synthetic graph (use
//! `--release`); its entries are kept in the same file and checked only when
//! the variable is set.

use ch_analysis::{findings, simulate};
use ch_engine::{par_bfs, tier0_analysis, Dir, EdgeFilter};
use ch_ingest::{build_graph, IngestOptions};
use ch_model::flags;
use ch_store::{Filter, Graph};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------ hashing

fn fnv(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for &b in *p {
            h ^= b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    let mut z = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Order-independent multiset hash: `count:hash`.
#[derive(Default)]
struct SetHash(u64, u64);
impl SetHash {
    fn add(&mut self, parts: &[&[u8]]) {
        self.0 += 1;
        self.1 = self.1.wrapping_add(fnv(parts));
    }
    fn get(&self) -> Value {
        json!(format!("{}:{:016x}", self.0, self.1))
    }
}

fn seq_hash(items: impl IntoIterator<Item = String>) -> Value {
    let mut n = 0u64;
    let mut h = 0u64;
    for s in items {
        n += 1;
        h = fnv(&[&h.to_le_bytes(), s.as_bytes()]);
    }
    json!(format!("{n}:{h:016x}"))
}

fn round(x: f64) -> String {
    format!("{x:.6}")
}

// ---------------------------------------------------------------- canonical

/// Ingest numbers nodes in object id order; the analysis below relies on it
/// for reproducible tie-breaks.
fn assert_canonical(g: &Graph) {
    let n = g.node_count() as u32;
    assert!((1..n).all(|i| g.oid(i - 1) < g.oid(i)), "nodes are not numbered by object id");
}

// ----------------------------------------------------------------- sections

fn graph_sets(g: &Graph) -> Value {
    let mut nodes: BTreeMap<String, SetHash> = BTreeMap::new();
    for id in 0..g.node_count() as u32 {
        nodes.entry(g.kind(id).as_str().to_string()).or_default().add(&[
            g.oid(id).as_bytes(),
            g.name(id).as_bytes(),
            &g.flags(id).to_le_bytes(),
        ]);
    }
    let mut edges: BTreeMap<String, SetHash> = BTreeMap::new();
    for u in 0..g.node_count() as u32 {
        let (ds, ks) = g.out_edges(u);
        for (&d, &k) in ds.iter().zip(ks) {
            edges.entry(g.edge_kind_name(k).to_string()).or_default().add(&[g.oid(u).as_bytes(), g.oid(d).as_bytes()]);
        }
    }
    json!({
        "nodes": nodes.iter().map(|(k, v)| (k.clone(), v.get())).collect::<Map<_, _>>(),
        "edges": edges.iter().map(|(k, v)| (k.clone(), v.get())).collect::<Map<_, _>>(),
    })
}

fn exposure(g: &Graph, unified: bool) -> Value {
    let f = EdgeFilter::traversable(g).unified_tier0(unified);
    let r = tier0_analysis(g, &f, 25);
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let bfs = par_bfs(g, &tier0, Dir::Reverse, &|s, d, k| f.permits(g, s, d, k));
    let mut exposed = SetHash::default();
    for u in 0..g.node_count() as u32 {
        let d = bfs.dist[u as usize];
        if d != u32::MAX && d > 0 && ch_engine::is_principal(g.kind(u)) {
            exposed.add(&[g.oid(u).as_bytes(), &d.to_le_bytes()]);
        }
    }
    json!({
        "tier0_nodes": tier0.len(),
        "exposed_principals": r.exposed_principals,
        "total_principals": r.total_principals,
        "max_depth": r.max_depth,
        "by_kind": r.exposure.iter().map(|k| format!("{}:{}/{}", k.kind, k.with_path, k.total)).collect::<Vec<_>>(),
        "exposed_set": exposed.get(),
        "choke_points": seq_hash(r.choke_points.iter().map(|c| {
            format!("{}|{}|{}|{}", g.oid(c.src), g.edge_kind_name(c.kind), g.oid(c.dst), round(c.flow))
        })),
    })
}

fn plan(g: &Graph) -> Value {
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let opts = simulate::PlanOptions { steps: 8, fixed_kinds: vec![], protect_target_membership: true, ..Default::default() };
    let p = simulate::plan(g, &tier0, &opts, &ch_query::Cancel::never());
    json!({
        "baseline": p.baseline,
        "steps": p.steps.iter().map(|s| {
            let mut es: Vec<String> = s.edges.iter().map(|e| format!("{}>{}>{}", g.oid(e.0), g.edge_kind_name(e.2), g.oid(e.1))).collect();
            es.sort();
            format!("{} cut={} after={} edges={}", g.name(s.node), s.principals_cut, s.exposed_after, seq_hash(es).as_str().unwrap())
        }).collect::<Vec<_>>(),
    })
}

fn findings_section(g: &Graph) -> Value {
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let res = findings::evaluate(g, &tier0, &ch_query::Cancel::never(), &|_, _| {});
    let mut out: Vec<String> = res
        .iter()
        .map(|r| {
            let mut items: Vec<String> = r.item_labels(g).into_iter().map(|(k, _)| k).collect();
            items.sort();
            let cut = r.exposure.as_ref().map(|e| e.principals_cut).unwrap_or(0);
            format!("{} n={} cut={} items={}", r.def.id, r.items.len(), cut, seq_hash(items).as_str().unwrap())
        })
        .collect();
    out.sort();
    json!(out)
}

const ADHOC: &[&str] = &[
    "MATCH (n) RETURN n.kind, count(*)",
    "MATCH (a)-[r]->(b) RETURN type(r), count(*)",
    "MATCH (u:User) WHERE u.description IS NULL RETURN count(u)",
    "MATCH (u:User) WHERE NOT u.nosuchprop = 1 RETURN count(u)",
    "MATCH (u:User) WHERE u.pwdlastset > '1650000000' RETURN count(u)",
    "MATCH (c:Computer) WHERE c.operatingsystem IN ['windows 7 professional', 'Ubuntu 22.04'] RETURN count(c)",
    "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN u.name",
    "MATCH (u:User)-[:MemberOf*1..2]->(g:Group) RETURN count(*)",
    "MATCH p = shortestPath((u:User {enabled:true})-[*1..]->(t {tier0:true})) RETURN p",
    "MATCH (u:User)-[:MemberOf]->(g)-[:AdminTo]->(c:Computer) RETURN count(*)",
    "MATCH (u:User) OPTIONAL MATCH (u)-[:HasSession]-(c:Computer) RETURN u.name, count(c)",
    "MATCH (g:Group)<-[:MemberOf]-(m) WITH g, count(m) AS c WHERE c > 2 RETURN g.name, c",
    "MATCH (a:User), (b:Group) WHERE a.admincount AND b.admincount RETURN count(*)",
    "MATCH (n:User) RETURN n.enabled AS e UNION MATCH (n:Computer) RETURN n.enabled AS e",
    "MATCH (u:User) RETURN CASE WHEN u.hasspn THEN 'spn' ELSE 'none' END AS s, count(*)",
    "MATCH (u:User) RETURN min(u.pwdlastset), max(u.pwdlastset), count(DISTINCT u.domain)",
];

fn chql(g: &Graph) -> Value {
    let mut out = Map::new();
    let queries = ch_query::PREBUILT.iter().map(|p| (p.id.to_string(), p.query)).chain(ADHOC.iter().enumerate().map(|(i, q)| (format!("adhoc-{i:02}"), *q)));
    for (id, q) in queries {
        let v = match ch_query::run(g, q, 100_000) {
            Err(e) => json!(format!("error: {e}")),
            Ok(r) => {
                let paths = q.contains("shortestPath") || q.contains("allShortestPaths") || q.contains("p =");
                let limited = q.to_ascii_uppercase().contains(" LIMIT ");
                let mut rows: Vec<String> = r
                    .rows
                    .iter()
                    .map(|row| {
                        let row: Vec<Value> = row
                            .iter()
                            .map(|v| match v {
                                Value::Array(a) if paths => json!([a.first(), a.last(), a.len()]),
                                Value::Number(n) if n.as_f64().is_some_and(|f| f.fract() != 0.0) => json!(round(n.as_f64().unwrap())),
                                v => v.clone(),
                            })
                            .collect();
                        serde_json::to_string(&row).unwrap()
                    })
                    .collect();
                rows.sort();
                if limited {
                    // Which rows a LIMIT keeps among ties is unspecified.
                    json!(format!("rows={} truncated={}", rows.len(), r.truncated))
                } else {
                    json!(format!("{} truncated={}", seq_hash(rows).as_str().unwrap(), r.truncated))
                }
            }
        };
        out.insert(id, v);
    }
    Value::Object(out)
}

fn filters_and_search(g: &Graph) -> Value {
    let filters = [
        r#"{"and":[{"kind":["User"]},{"truthy":"enabled"},{"not":{"is_null":{"key":"description"}}}]}"#,
        r#"{"or":[{"cmp":{"key":"operatingsystem","op":"contains","value":"server"}},{"cmp":{"key":"pwdlastset","op":"<","value":"1650000000"}}]}"#,
        r#"{"not":{"cmp":{"key":"domain","op":"eq","value":"synth.local"}}}"#,
        r#"{"cmp":{"key":"serviceprincipalnames","op":"starts_with","value":"MSSQL"}}"#,
        r#"{"and":[{"truthy":"tier0"},{"kind":["User","Group","Computer"]}]}"#,
    ];
    let mut out = Map::new();
    for (i, f) in filters.iter().enumerate() {
        let f: Filter = serde_json::from_str(f).unwrap();
        let hits = g.filter(&f);
        assert_eq!(hits, g.filter_scan(&f), "indexed filter differs from the JSON scan: {f:?}");
        out.insert(format!("filter-{i}"), seq_hash(hits.iter().map(|id| g.oid(id).to_string())));
    }
    for t in ["user1", "admin", "synth.local", "dc", "S-1-5-21-1000000001-2000000002-3000000003-512", "corp"] {
        out.insert(format!("search-{t}"), json!(g.search(t, None, 12).iter().map(|&id| g.name(id).to_string()).collect::<Vec<_>>()));
    }
    Value::Object(out)
}

fn analyse(inputs: &[PathBuf]) -> Value {
    let b = build_graph(inputs, &IngestOptions::default()).expect("ingest");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let sets = graph_sets(&b.graph);
    assert_canonical(&b.graph);
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete edge compositions: {bad:#?}");
    let g = b.graph;
    let _ = g.columns();
    json!({
        "graph": sets,
        "tier0_unified": exposure(&g, true),
        "tier0_per_realm": exposure(&g, false),
        "plan": plan(&g),
        "findings": findings_section(&g),
        "chql": chql(&g),
        "filter_search": filters_and_search(&g),
    })
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-accuracy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn synth(name: &str, users: u32, seed: u64) -> Value {
    let d = scratch(name);
    let cfg = ch_synth::SynthConfig { users, computers: users / 5, groups: (users / 20).max(50), seed };
    let opts = ch_synth::SynthOptions { domains: 2, rich_props: true };
    ch_synth::generate_with(&cfg, &opts, &d).unwrap();
    let v = analyse(std::slice::from_ref(&d));
    let _ = std::fs::remove_dir_all(&d);
    v
}

fn fixture(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ingest/tests/fixtures/corp").join(sub)
}

/// Differences between two JSON trees as `path: old -> new` lines.
fn diff(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: std::collections::BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                let p = format!("{path}.{k}");
                match (x.get(k), y.get(k)) {
                    (Some(u), Some(v)) => diff(&p, u, v, out),
                    (u, v) => out.push(format!("{p}: {} -> {}", u.unwrap_or(&Value::Null), v.unwrap_or(&Value::Null))),
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (u, v)) in x.iter().zip(y).enumerate() {
                diff(&format!("{path}[{i}]"), u, v, out);
            }
        }
        _ if a != b => out.push(format!("{path}: {a} -> {b}")),
        _ => {}
    }
}

#[test]
fn accuracy_golden() {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/accuracy.json");
    let large = std::env::var_os("COPPERHOUND_ACCURACY_LARGE").is_some();
    let mut now = Map::new();
    now.insert("synth-3k".into(), synth("synth3k", 3_000, 7));
    now.insert("corp-sharphound".into(), analyse(&[fixture("sharphound")]));
    now.insert("corp-ldif".into(), analyse(&[fixture("ldif")]));
    if large {
        now.insert("synth-100k".into(), synth("synth100k", 100_000, 11));
    }
    let old: Map<String, Value> = std::fs::read_to_string(&golden_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if std::env::var_os("COPPERHOUND_UPDATE_GOLDEN").is_some() {
        let mut merged = old.clone();
        for (k, v) in &now {
            merged.insert(k.clone(), v.clone());
        }
        std::fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        std::fs::write(&golden_path, serde_json::to_string_pretty(&Value::Object(merged)).unwrap() + "\n").unwrap();
        eprintln!("wrote {}", golden_path.display());
        return;
    }
    let mut lines = Vec::new();
    for (k, v) in &now {
        match old.get(k) {
            None => lines.push(format!("{k}: no golden entry (run with COPPERHOUND_UPDATE_GOLDEN=1)")),
            Some(o) => diff(k, o, v, &mut lines),
        }
    }
    assert!(
        lines.is_empty(),
        "accuracy golden mismatch ({} differences). If intended, regenerate with \
         COPPERHOUND_UPDATE_GOLDEN=1 and review the diff.\n{}",
        lines.len(),
        lines.join("\n")
    );
}
