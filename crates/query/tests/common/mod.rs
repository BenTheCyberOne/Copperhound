//! Differential check: every query must return exactly the same result with
//! predicate pushdown on (and verified node by node) as with it off.

#![allow(dead_code)]

use ch_query::{run_opts, Cancel, ExecOptions, QueryResult, MAX_LIMIT};
use ch_store::Graph;
use std::time::Duration;

pub const OFF: ExecOptions = ExecOptions { pushdown: false, verify: false };
pub const ON: ExecOptions = ExecOptions { pushdown: true, verify: true };

/// Result as a canonical, order-insensitive value: columns, the multiset of
/// rows, node / edge / path sets and the truncation flag.
#[derive(Debug, PartialEq)]
pub struct Canon {
    columns: Vec<String>,
    rows: Vec<String>,
    nodes: Vec<u32>,
    edges: Vec<(u32, u32, u16)>,
    paths: Vec<Vec<u32>>,
    truncated: bool,
}

pub fn canon(r: &QueryResult) -> Canon {
    let mut rows: Vec<String> = r.rows.iter().map(|x| serde_json::to_string(x).unwrap()).collect();
    rows.sort();
    let mut nodes = r.nodes.clone();
    nodes.sort_unstable();
    let mut edges = r.edges.clone();
    edges.sort_unstable();
    let mut paths = r.paths.clone();
    paths.sort();
    Canon { columns: r.columns.clone(), rows, nodes, edges, paths, truncated: r.truncated }
}

/// A trailing `LIMIT n` makes the kept rows depend on thread timing; drop it
/// so whole result sets are compared.
pub fn strip_limit(q: &str) -> String {
    let t = q.trim_end();
    let up = t.to_ascii_uppercase();
    if let Some(i) = up.rfind(" LIMIT ") {
        if t[i + 7..].trim().chars().all(|c| c.is_ascii_digit()) {
            return t[..i].to_string();
        }
    }
    t.to_string()
}

pub fn exec(g: &Graph, q: &str, o: &ExecOptions) -> Result<QueryResult, String> {
    run_opts(g, q, MAX_LIMIT, MAX_LIMIT, &Cancel::new(Some(Duration::from_secs(120))), o).map_err(|e| format!("{}: {}", e.code, e.message))
}

/// Run `q` (trailing LIMIT removed) with pushdown off and on; panic on any
/// difference. Returns the result size (to keep tests from being vacuous).
pub fn check(g: &Graph, q: &str) -> usize {
    assert!(g.columns_ready().is_some(), "build columns first");
    let q = strip_limit(q);
    let off = exec(g, &q, &OFF);
    let on = exec(g, &q, &ON);
    match (&off, &on) {
        (Err(a), Err(b)) => {
            assert_eq!(a, b, "different errors for {q}");
            0
        }
        (Ok(a), Ok(b)) => {
            let (ca, cb) = (canon(a), canon(b));
            if a.truncated {
                // Hit the row ceiling: which rows are kept depends on thread
                // timing, so only the shape can be compared.
                assert!(b.truncated && a.columns == b.columns, "pushdown changed a truncated result of {q}");
                return 0;
            }
            if ca != cb {
                let again = canon(&exec(g, &q, &OFF).unwrap());
                assert!(
                    again != ca,
                    "pushdown changed the result of {q}\noff: {} rows {} nodes\non:  {} rows {} nodes",
                    ca.rows.len(),
                    ca.nodes.len(),
                    cb.rows.len(),
                    cb.nodes.len()
                );
                panic!("query is nondeterministic even without pushdown; cannot compare: {q}");
            }
            a.rows.len().max(a.nodes.len())
        }
        _ => panic!("pushdown changed success/failure of {q}: off {:?} on {:?}", off.as_ref().err(), on.as_ref().err()),
    }
}
