//! Ingest micro-benchmarks: `cargo run --release --example scan_bench -- FILE`
//! Times the structural scanner alone, then record parsing with and without
//! edge extraction, to locate serial bottlenecks.
use rayon::prelude::*;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: scan_bench FILE");
    let f = std::fs::File::open(&path)?;
    let map = unsafe { memmap2::Mmap::map(&f)? };
    let mb = map.len() as f64 / 1048576.0;

    let t = Instant::now();
    let ranges = ch_ingest::scan::scan_records(&map)?.ranges;
    println!(
        "scan        {:>6.0} MB/s  ({} records)",
        mb / t.elapsed().as_secs_f64(),
        ranges.len()
    );

    let t = Instant::now();
    let ok: usize = ranges
        .par_chunks(4096)
        .map(|c| {
            c.iter()
                .filter(|(a, b)| {
                    serde_json::from_slice::<serde::de::IgnoredAny>(&map[*a..*b]).is_ok()
                })
                .count()
        })
        .sum();
    println!(
        "validate    {:>6.0} MB/s  ({ok} ok)",
        mb / t.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    let ok: usize = ranges
        .par_chunks(4096)
        .map(|c| {
            c.iter()
                .filter(|(a, b)| {
                    serde_json::from_slice::<ch_ingest::sharphound::Record>(&map[*a..*b]).is_ok()
                })
                .count()
        })
        .sum();
    println!(
        "deserialize {:>6.0} MB/s  ({ok} ok)",
        mb / t.elapsed().as_secs_f64()
    );

    let shared = ch_ingest::emit::Shared::new(true);
    let t = Instant::now();
    let edges: usize = ranges
        .par_chunks(4096)
        .map(|c| {
            let mut em = ch_ingest::emit::Emitter::new(&shared, None);
            for (a, b) in c {
                if let Ok(r) = serde_json::from_slice::<ch_ingest::sharphound::Record>(&map[*a..*b])
                {
                    ch_ingest::sharphound::extract(r, &mut em);
                }
            }
            em.finish().edges.len()
        })
        .sum();
    println!(
        "extract     {:>6.0} MB/s  ({edges} edges, {} ids)",
        mb / t.elapsed().as_secs_f64(),
        shared.interner.len()
    );
    Ok(())
}
