//! Differential dump used by accuracy audits.
//!
//! `ch_dump <graph> summary` prints per-node-kind and per-edge-kind counts plus
//! order-insensitive set hashes; `ch_dump <graph> nodes <out>` and
//! `ch_dump <graph> edges <out> [KIND,..]` write sorted TSV for diffing.
use std::io::Write;

fn fnv(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for p in parts {
        for &b in *p {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    let mut z = h.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn canon_props(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(v) => serde_json::to_string(&v).unwrap(),
        Err(_) => s.to_string(),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let g = ch_store::Graph::open(std::path::Path::new(&a[1])).expect("open");
    let n = g.node_count() as u32;
    match a[2].as_str() {
        "summary" => {
            use std::collections::BTreeMap;
            let mut nk: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
            for id in 0..n {
                let k = g.kind(id).as_str().to_string();
                let h = fnv(&[g.oid(id).as_bytes(), g.name(id).as_bytes(), &g.flags(id).to_le_bytes()]);
                let hp = fnv(&[g.oid(id).as_bytes(), canon_props(g.props(id)).as_bytes()]);
                let e = nk.entry(k).or_default();
                e.0 += 1;
                e.1 = e.1.wrapping_add(h);
                e.2 = e.2.wrapping_add(hp);
            }
            for (k, (c, h, hp)) in &nk {
                println!("node\t{k}\t{c}\t{h:016x}\tprops={hp:016x}");
            }
            let mut ek: BTreeMap<String, (u64, u64)> = BTreeMap::new();
            for u in 0..n {
                let (ds, ks) = g.out_edges(u);
                for (&d, &k) in ds.iter().zip(ks) {
                    let h = fnv(&[g.oid(u).as_bytes(), g.oid(d).as_bytes()]);
                    let e = ek.entry(g.edge_kind_name(k).to_string()).or_default();
                    e.0 += 1;
                    e.1 = e.1.wrapping_add(h);
                }
            }
            for (k, (c, h)) in &ek {
                println!("edge\t{k}\t{c}\t{h:016x}");
            }
        }
        "nodes" => {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&a[3]).unwrap());
            let mut rows: Vec<String> = (0..n)
                .map(|id| {
                    format!(
                        "{}\t{}\t{}\t{}\t{}",
                        g.oid(id),
                        g.kind(id).as_str(),
                        g.name(id),
                        g.flags(id),
                        canon_props(g.props(id))
                    )
                })
                .collect();
            rows.sort();
            for r in rows {
                writeln!(f, "{r}").unwrap();
            }
        }
        "edges" => {
            let want: Option<Vec<String>> = a.get(4).map(|s| s.split(',').map(str::to_string).collect());
            let mut f = std::io::BufWriter::new(std::fs::File::create(&a[3]).unwrap());
            let mut rows = Vec::new();
            for u in 0..n {
                let (ds, ks) = g.out_edges(u);
                for (&d, &k) in ds.iter().zip(ks) {
                    let name = g.edge_kind_name(k);
                    if want.as_ref().is_some_and(|w| !w.iter().any(|x| x == name)) {
                        continue;
                    }
                    rows.push(format!("{}\t{}\t{}\t{}\t{}", name, g.oid(u), g.oid(d), g.name(u), g.name(d)));
                }
            }
            rows.sort();
            for r in rows {
                writeln!(f, "{r}").unwrap();
            }
        }
        m => panic!("unknown mode {m}"),
    }
}
