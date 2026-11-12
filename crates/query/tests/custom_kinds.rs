//! Pushdown on custom (OpenGraph) kinds: `n.kind` reads the custom kind name,
//! and the column fast path must agree with evaluating the predicate.

mod common;

use ch_query::{run_with, Cancel};
use serde_json::json;
use std::fs;

#[test]
fn kind_predicates_on_custom_kinds() {
    let d = std::env::temp_dir().join(format!("ch-q-custom-kinds-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let nodes: Vec<_> = (0..10)
        .map(|i| {
            let kind = ["PLC", "OTDevice", "User", "GHRepo"][i % 4];
            json!({"id": format!("n{i}"), "kinds": [kind], "properties": {"name": format!("N{i}")}})
        })
        .collect();
    fs::write(d.join("og.json"), json!({"graph": {"nodes": nodes}}).to_string()).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&d), &ch_ingest::IngestOptions::default()).unwrap().graph;
    g.columns();
    let count = |q: &str| run_with(&g, q, 100, &Cancel::never()).unwrap().rows[0][0].clone();
    assert_eq!(count("MATCH (n) WHERE n.kind = 'PLC' RETURN count(n)"), json!(3));
    assert_eq!(count("MATCH (n) WHERE n.kind IN ['PLC', 'OTDevice'] RETURN count(n)"), json!(6));
    assert_eq!(count("MATCH (n) WHERE n.kind STARTS WITH 'GH' RETURN count(n)"), json!(2));
    for q in [
        "MATCH (n) WHERE n.kind = 'PLC' RETURN n",
        "MATCH (n) WHERE n.kind = 'plc' RETURN n",
        "MATCH (n) WHERE n.kind IN ['PLC', 'OTDevice'] RETURN n",
        "MATCH (n) WHERE n.kind < 'Q' RETURN n",
        "MATCH (n) WHERE NOT n.kind = 'User' RETURN n",
        "MATCH (n) WHERE n.kind CONTAINS 'Dev' OR n.kind = 'User' RETURN n",
    ] {
        common::check(&g, q);
    }
    let _ = fs::remove_dir_all(&d);
}

/// A comparison with null is never true, pushed down or not.
#[test]
fn null_equality_is_false() {
    let d = std::env::temp_dir().join(format!("ch-q-nulls-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let nodes: Vec<_> = (0..6)
        .map(|i| {
            let props = if i % 2 == 0 { json!({"name": format!("U{i}"), "email": format!("u{i}@x")}) } else { json!({"name": format!("U{i}")}) };
            json!({"id": format!("S-1-5-21-1-1-1-{}", 1000 + i), "kinds": ["User"], "properties": props})
        })
        .collect();
    fs::write(d.join("og.json"), json!({"graph": {"nodes": nodes}}).to_string()).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&d), &ch_ingest::IngestOptions::default()).unwrap().graph;
    g.columns();
    let count = |q: &str| run_with(&g, q, 100, &Cancel::never()).unwrap().rows[0][0].clone();
    assert_eq!(count("MATCH (u:User) WHERE u.email = null RETURN count(u)"), json!(0));
    assert_eq!(count("MATCH (u:User {email: null}) RETURN count(u)"), json!(0));
    assert_eq!(count("MATCH (u:User) WHERE u.email IS NULL RETURN count(u)"), json!(3));
    // Two users without an email do not share one.
    assert_eq!(count("MATCH (a:User), (b:User) WHERE a <> b AND a.email = b.email RETURN count(*)"), json!(0));
    for q in ["MATCH (u:User) WHERE u.email = null RETURN u", "MATCH (u:User {email: null}) RETURN u", "MATCH (u:User) WHERE NOT u.email = null RETURN u"] {
        common::check(&g, q);
    }
    let _ = fs::remove_dir_all(&d);
}
