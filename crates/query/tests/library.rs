mod common;

use ch_query::{run_with, Cancel, PREBUILT};
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[test]
fn every_prebuilt_query_runs() {
    let dir = std::env::temp_dir().join(format!("ch-library-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 20_000, computers: 4_000, groups: 1_000, seed: 11 }, &dir).unwrap();
    let built = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap();
    let g = built.graph;

    let mut ids = HashSet::new();
    let mut slow = Vec::new();
    for p in PREBUILT {
        assert!(ids.insert(p.id), "duplicate id {}", p.id);
        assert!(!p.tags.is_empty(), "{} has no tags", p.id);
        let t = Instant::now();
        let r = run_with(&g, p.query, 1000, &Cancel::new(Some(Duration::from_secs(60))))
            .unwrap_or_else(|e| panic!("{} failed: {e}\n{}", p.id, p.query));
        let ms = t.elapsed().as_millis();
        if ms > 5_000 {
            slow.push((p.id, ms));
        }
        let _ = r;
    }
    assert!(PREBUILT.len() >= 80, "only {} prebuilt queries", PREBUILT.len());
    assert!(slow.is_empty(), "slow queries: {slow:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn timeout_and_cancel() {
    let dir = std::env::temp_dir().join(format!("ch-cancel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 5_000, computers: 1_000, groups: 300, seed: 2 }, &dir).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    let q = "MATCH (u:User)-[*1..]->(c:Computer) RETURN u, c LIMIT 100000";

    let e = run_with(&g, q, 1000, &Cancel::new(Some(Duration::ZERO))).unwrap_err();
    assert_eq!(e.code, "timeout");
    let c = Cancel::never();
    c.cancel();
    let e = run_with(&g, q, 1000, &c).unwrap_err();
    assert_eq!(e.code, "cancelled");
    let e = run_with(&g, "MATCH (n RETURN n", 10, &Cancel::never()).unwrap_err();
    assert_eq!(e.code, "syntax");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Pushdown on vs off: identical results for every library query.
#[test]
fn prebuilt_queries_pushdown_is_invisible() {
    let dir = std::env::temp_dir().join(format!("ch-library-ch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 3_000, computers: 600, groups: 200, seed: 13 }, &dir).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    g.columns();
    let mut hits = 0;
    for p in PREBUILT {
        hits += common::check(&g, p.query);
    }
    assert!(hits > 0);
    let _ = std::fs::remove_dir_all(&dir);
}
