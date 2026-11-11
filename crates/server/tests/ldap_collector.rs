//! The LDAP collector's LDIF writer is faithful: re-emitting a realistic AD
//! LDIF export (the synthetic generator's, with SIDs, GUIDs and security
//! descriptors as binary values) through `ldif_entry` yields the same graph.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ldap3::SearchEntry;
use ch_ingest::{build_graph, IngestOptions};
use ch_server::ldapcollect::ldif_entry;
use std::collections::HashMap;

fn parse(ldif: &str) -> Vec<SearchEntry> {
    let mut out = Vec::new();
    for block in ldif.split("\n\n") {
        let mut e = SearchEntry { dn: String::new(), attrs: HashMap::new(), bin_attrs: HashMap::new() };
        for line in block.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            if let Some((k, v)) = line.split_once(":: ") {
                let b = STANDARD.decode(v.trim()).expect("base64");
                if k == "dn" {
                    e.dn = String::from_utf8(b).unwrap();
                } else {
                    // ldap3 reports UTF-8 values as strings, others as binary.
                    match String::from_utf8(b.clone()) {
                        Ok(s) => e.attrs.entry(k.to_string()).or_default().push(s),
                        Err(_) => e.bin_attrs.entry(k.to_string()).or_default().push(b),
                    }
                }
            } else if let Some((k, v)) = line.split_once(": ") {
                if k == "dn" {
                    e.dn = v.to_string();
                } else {
                    e.attrs.entry(k.to_string()).or_default().push(v.to_string());
                }
            }
        }
        if !e.dn.is_empty() {
            out.push(e);
        }
    }
    out
}

#[test]
fn rewritten_ldif_ingests_identically() {
    let base = std::env::temp_dir().join(format!("ch-ldapw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (a, b) = (base.join("a"), base.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let orig = a.join("synth.ldif");
    ch_synth::generate_ldif(&ch_synth::SynthConfig { users: 400, computers: 80, groups: 40, seed: 7 }, &orig).unwrap();
    // RFC 2849 unfolding (the generator wraps long lines like ldifde).
    let text = std::fs::read_to_string(&orig).unwrap().replace("\r\n", "\n").replace("\n ", "");
    let entries = parse(&text);
    assert!(entries.len() > 500);
    let mut out = Vec::new();
    for e in &entries {
        ldif_entry(&mut out, e, &[]);
    }
    std::fs::write(b.join("rewritten.ldif"), &out).unwrap();
    let ga = build_graph(std::slice::from_ref(&a), &IngestOptions::default()).unwrap();
    let gb = build_graph(std::slice::from_ref(&b), &IngestOptions::default()).unwrap();
    assert_eq!(gb.ingest.parse_errors, 0, "{:?}", gb.ingest.first_error);
    let (x, y) = (&ga.graph, &gb.graph);
    assert_eq!((x.node_count(), x.edge_count()), (y.node_count(), y.edge_count()));
    let set = |g: &ch_store::Graph| {
        let mut v: Vec<String> = (0..g.node_count() as u32)
            .flat_map(|s| {
                let (ds, ks) = g.out_edges(s);
                ds.iter().zip(ks).map(move |(&d, &k)| format!("{}|{}|{}", g.oid(s), g.edge_kind_name(k), g.oid(d))).collect::<Vec<_>>()
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(set(x), set(y), "same edges");
    let _ = std::fs::remove_dir_all(&base);
}
