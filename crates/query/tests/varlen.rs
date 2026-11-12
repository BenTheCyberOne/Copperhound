//! Variable-length relationships return every end node reachable by a walk
//! whose length is in range, not only nodes whose shortest distance is.

use ch_query::{run_with, Cancel};
use serde_json::Value;
use std::collections::BTreeSet;

fn pairs(g: &ch_store::Graph, q: &str) -> BTreeSet<(String, String)> {
    let r = run_with(g, q, 10_000_000, &Cancel::never()).unwrap_or_else(|e| panic!("{q}: {e}"));
    r.rows
        .iter()
        .map(|row| {
            let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
            (s(&row[0]), s(&row[1]))
        })
        .collect()
}

#[test]
fn var_length_matches_fixed_length_patterns() {
    let dir = std::env::temp_dir().join(format!("ch-varlen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 600, computers: 120, groups: 80, seed: 5 }, &dir).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    let one = pairs(&g, "MATCH (a)-[:MemberOf]->(c) RETURN DISTINCT a.objectid, c.objectid");
    let two = pairs(&g, "MATCH (a)-[:MemberOf]->()-[:MemberOf]->(c) RETURN DISTINCT a.objectid, c.objectid");
    let three = pairs(&g, "MATCH (a)-[:MemberOf]->()-[:MemberOf]->()-[:MemberOf]->(c) RETURN DISTINCT a.objectid, c.objectid");
    assert!(!two.is_empty() && !one.is_disjoint(&two), "the graph must have nodes reachable at both 1 and 2 hops");
    assert_eq!(pairs(&g, "MATCH (a)-[:MemberOf*2..2]->(c) RETURN DISTINCT a.objectid, c.objectid"), two);
    assert_eq!(pairs(&g, "MATCH (a)-[:MemberOf*1..2]->(c) RETURN DISTINCT a.objectid, c.objectid"), &one | &two);
    assert_eq!(pairs(&g, "MATCH (a)-[:MemberOf*2..3]->(c) RETURN DISTINCT a.objectid, c.objectid"), &two | &three);
    // Paths returned for *2..2 have exactly two hops.
    let r = run_with(&g, "MATCH p = (a)-[:MemberOf*2..2]->(c) RETURN p", 100_000, &Cancel::never()).unwrap();
    assert!(!r.paths.is_empty());
    assert!(r.paths.iter().all(|p| p.len() == 3), "every *2..2 path has 3 nodes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Starts that are also targets: shortestPath gives the same answer however
/// many starts there are, and allShortestPaths finds them too.
#[test]
fn shortest_paths_from_starts_inside_the_targets() {
    use serde_json::json;
    let dir = std::env::temp_dir().join(format!("ch-sp-inside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // G0 -> G1 -> G2 plus 100 unrelated groups (over the 64-start threshold).
    let sid = |i: usize| format!("S-1-5-21-7-7-7-{}", 2000 + i);
    let nodes: Vec<_> = (0..103).map(|i| json!({"id": sid(i), "kinds": ["Group"], "properties": {"name": format!("G{i}")}})).collect();
    let edges = vec![
        json!({"kind": "MemberOf", "start": {"value": sid(0)}, "end": {"value": sid(1)}}),
        json!({"kind": "MemberOf", "start": {"value": sid(1)}, "end": {"value": sid(2)}}),
    ];
    std::fs::write(dir.join("og.json"), json!({"graph": {"nodes": nodes, "edges": edges}}).to_string()).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    let ends = |q: &str| -> BTreeSet<(String, String)> {
        let r = run_with(&g, q, 1000, &Cancel::never()).unwrap_or_else(|e| panic!("{q}: {e}"));
        r.paths.iter().map(|p| (g.name(p[0]).to_string(), g.name(*p.last().unwrap()).to_string())).collect()
    };
    let want: BTreeSet<(String, String)> = [("G0", "G1"), ("G1", "G2")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    // Few starts (per-start search) and many starts (one reverse BFS).
    assert_eq!(ends("MATCH p = shortestPath((a:Group)-[:MemberOf*1..]->(b:Group)) WHERE a.name IN ['G0', 'G1'] RETURN p"), want);
    assert_eq!(ends("MATCH p = shortestPath((a:Group)-[:MemberOf*1..]->(b:Group)) RETURN p"), want);
    let r = run_with(&g, "MATCH p = allShortestPaths((a:Group {name: 'G1'})-[:MemberOf*1..]->(b:Group)) RETURN p", 1000, &Cancel::never()).unwrap();
    // The result is a subgraph: G1 -MemberOf-> G2.
    let got: Vec<(String, String)> = r.edges.iter().map(|&(a, b, _)| (g.name(a).to_string(), g.name(b).to_string())).collect();
    assert_eq!(got, vec![("G1".to_string(), "G2".to_string())], "allShortestPaths from a start that is also a target");
    let _ = std::fs::remove_dir_all(&dir);
}
