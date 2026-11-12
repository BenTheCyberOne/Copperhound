//! Resource limits on untrusted queries: anything a viewer can send must fail
//! cleanly instead of overflowing the stack, running past its timeout or
//! exhausting memory.

use ch_query::{parse_syntax, run_with, Cancel};
use std::time::{Duration, Instant};

fn too_deep(q: &str) {
    let e = parse_syntax(q).expect_err("must be rejected");
    assert!(e.message.contains("nested too deeply"), "{}", e.message);
}

/// Binary-operator chains build a left-nested tree as deep as the chain is
/// long; they count against the nesting limit like parentheses do.
#[test]
fn long_operator_chains_are_rejected() {
    // Run on a small stack, like a server worker thread.
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(|| {
            let n = 20_000; // under the 256 KiB query size limit; 5,000 overflowed before
            too_deep(&format!("RETURN {}", vec!["1"; n].join("+")));
            too_deep(&format!("RETURN {}", vec!["2"; n].join("*")));
            too_deep(&format!("MATCH (n) WHERE {} RETURN n", vec!["n.x = 1"; n].join(" OR ")));
            too_deep(&format!("MATCH (n) WHERE {} RETURN n", vec!["n.x = 1"; n].join(" AND ")));
            too_deep(&format!("RETURN {}", vec!["1"; n].join(" = ")));
            too_deep(&format!("RETURN {}1", "+".repeat(n)));
            too_deep(&format!("RETURN {}1", "-".repeat(n)));
            too_deep(&format!("RETURN [1]{}", "[0]".repeat(n)));
            too_deep(&format!("MATCH (n) RETURN n{}", ".a".repeat(n)));
            // Ordinary sizes still parse.
            parse_syntax(&format!("RETURN {}", vec!["1"; 150].join("+"))).unwrap();
            parse_syntax(&format!("MATCH (n) WHERE {} RETURN n", vec!["n.x = 1"; 60].join(" OR "))).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}

fn tiny_graph() -> ch_store::Graph {
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    ch_store::Graph::build(ch_store::GraphParts {
        kinds: vec![1],
        flags: vec![0],
        names: vec![Some("A@X".into())],
        oids: vec!["S-1".into()],
        props: vec![None],
        edge_chunks: vec![Vec::new()],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap()
    .0
}

/// List comprehensions and quantifiers poll the timeout.
#[test]
fn comprehensions_honour_the_timeout() {
    let g = tiny_graph();
    let q = "RETURN size([x IN range(1,1000000) WHERE any(y IN range(1,20) WHERE y = x + 100)])";
    let t = Instant::now();
    let e = run_with(&g, q, 10, &Cancel::new(Some(Duration::from_millis(50)))).unwrap_err();
    assert_eq!(e.code, "timeout", "{}", e.message);
    assert!(t.elapsed() < Duration::from_secs(2), "stopped after {:?}", t.elapsed());
}

/// Values a query builds itself are budgeted: doubling strings or nesting
/// ranges stops with an error instead of exhausting memory.
#[test]
fn built_values_are_budgeted() {
    let g = tiny_graph();
    let doubling = format!("WITH 'xxxxxxxx' AS s {} RETURN size(s)", vec!["WITH s+s AS s"; 40].join(" "));
    for q in [
        doubling.as_str(),
        "RETURN size([x IN range(1,1000000) | range(1,1000000)])",
    ] {
        let e = run_with(&g, q, 10, &Cancel::never()).unwrap_err();
        assert_eq!(e.code, "too_large", "{q}: {}", e.message);
    }
    // A single list is capped at a million elements: concatenation past it gives null.
    let r = run_with(&g, "WITH range(1,1000000) AS l WITH l+l AS l RETURN size(l)", 10, &Cancel::never()).unwrap();
    assert_eq!(r.rows[0], vec![serde_json::Value::Null]);
    // Ordinary use stays well inside the budget.
    let r = run_with(&g, "RETURN size(range(1,1000000)), size([x IN range(1,1000) | x * 2]), replace('abc','b','xx')", 10, &Cancel::never()).unwrap();
    assert_eq!(r.rows[0], vec![serde_json::json!(1000000), serde_json::json!(1000), serde_json::json!("axxc")]);
}
