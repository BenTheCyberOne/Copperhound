//! Times edge composition on a built graph: the first edge of every derived
//! kind. `cargo run --release -p ch-ingest --example explain_bench -- <graph dir>`

use ch_ingest::postprocess::explain::{compose, COMPOSITE_KINDS};
use ch_store::Graph;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).expect("graph directory");
    let g = Graph::open(std::path::Path::new(&dir))?;
    println!("{} nodes, {} edges", g.node_count(), g.edge_count());
    for name in COMPOSITE_KINDS {
        let Some(k) = g.edge_kind_id(name) else { continue };
        let first = (0..g.node_count() as u32).find_map(|s| {
            let (ds, ks) = g.out_edges(s);
            ds.iter().zip(ks).find(|(_, &kk)| kk == k).map(|(&d, _)| (s, d))
        });
        let Some((s, d)) = first else { continue };
        let t = Instant::now();
        let c = compose(&g, s, d, k).expect("edge exists");
        println!(
            "{name:<24} {:>8.1} ms  complete={} edges={} notes={}",
            t.elapsed().as_secs_f64() * 1e3,
            c.complete,
            c.edges.len(),
            c.notes.len()
        );
    }
    Ok(())
}
