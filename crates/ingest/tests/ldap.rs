//! Raw directory dumps (LDIF, AD Explorer snapshots) against the SharpHound
//! JSON of the same directory. Fixture: `tests/fixtures/corp` (see
//! `tests/fixtures/gen_corp.py`).

use ch_ingest::ldap::{self, adexplorer, A, NEED_ALL};
use ch_ingest::{build_graph, scan, Built, IngestOptions};
use ch_model::{flags, NodeKind};
use ch_store::Graph;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-1000-2000-3000";

fn fixture(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corp").join(sub)
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-ldap-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn build(p: &Path) -> Built {
    let b = build_graph(&[p.to_path_buf()], &IngestOptions::default()).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    b
}

const FLAG_MASK: u32 =
    flags::ENABLED | flags::ADMINCOUNT | flags::UNCONSTRAINED_DELEGATION | flags::DONT_REQ_PREAUTH | flags::HAS_SPN | flags::TIER0;

type Nodes = BTreeMap<String, (NodeKind, String, u32)>;
type Edges = BTreeSet<(String, String, String)>;

fn sets(g: &Graph) -> (Nodes, Edges) {
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeSet::new();
    for i in 0..g.node_count() as u32 {
        nodes.insert(g.oid(i).to_string(), (g.kind(i), g.name(i).to_string(), g.flags(i) & FLAG_MASK));
        let (ds, ks) = g.out_edges(i);
        for (&d, &k) in ds.iter().zip(ks) {
            edges.insert((g.oid(i).to_string(), g.oid(d).to_string(), g.edge_kind_name(k).to_string()));
        }
    }
    (nodes, edges)
}

fn diff<T: Ord + std::fmt::Debug + Clone>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> String {
    let only_a: Vec<_> = a.difference(b).cloned().collect();
    let only_b: Vec<_> = b.difference(a).cloned().collect();
    format!("only in left: {only_a:#?}\nonly in right: {only_b:#?}")
}

fn assert_same(left: &Graph, right: &Graph) {
    let (na, ea) = sets(left);
    let (nb, eb) = sets(right);
    let na_set: BTreeSet<_> = na.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let nb_set: BTreeSet<_> = nb.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    assert!(na_set == nb_set, "node sets differ:\n{}", diff(&na_set, &nb_set));
    assert!(ea == eb, "edge sets differ:\n{}", diff(&ea, &eb));
}

/// The LDIF dump (ldapsearch + ldifde + gzip schema) and the SharpHound JSON
/// of the same directory produce identical node and edge sets, including the
/// derived DCSync / Tier Zero / ADCS (ESC1, ESC4, ESC13, GoldenCert, …) edges.
#[test]
fn ldif_equals_sharphound() {
    let l = build(&fixture("ldif"));
    let s = build(&fixture("sharphound"));
    assert_eq!(l.ingest.files, 3);
    assert_same(&l.graph, &s.graph);
    // The equivalence is not vacuous.
    let (n, e) = sets(&l.graph);
    assert!(n.len() > 40 && e.len() > 80, "{} nodes, {} edges", n.len(), e.len());
    let adcs = l.post.passes.iter().find(|p| p.0 == "adcs").unwrap().1;
    assert!(adcs > 0);
    if std::env::var_os("CH_DUMP").is_some() {
        for (k, v) in &n {
            eprintln!("N {k} {v:?}");
        }
        for x in &e {
            eprintln!("E {x:?}");
        }
    }
}

fn edges_between(g: &Graph, a: &str, b: &str) -> Vec<String> {
    let (ia, ib) = (g.lookup(a).unwrap_or_else(|| panic!("{a}")), g.lookup(b).unwrap_or_else(|| panic!("{b}")));
    let (ds, ks) = g.out_edges(ia);
    let mut v: Vec<String> =
        ds.iter().zip(ks).filter(|(d, _)| **d == ib).map(|(_, k)| g.edge_kind_name(*k).to_string()).collect();
    v.sort();
    v
}

#[test]
fn ldif_details() {
    let b = build(&fixture("ldif"));
    let g = &b.graph;
    let u = |r: u32| format!("{D}-{r}");
    // objectSid / objectGUID decoding, names, kinds.
    let alice = g.lookup(&u(1104)).unwrap();
    assert_eq!(g.name(alice), "ALICE@CORP.LOCAL");
    assert_eq!(g.kind(alice), NodeKind::User);
    assert_eq!(g.kind(g.lookup(&u(1109)).unwrap()), NodeKind::User); // gMSA
    assert_eq!(g.kind(g.lookup("00000002-0000-4000-8000-000000000002").unwrap()), NodeKind::Ou);
    assert_eq!(g.name(g.lookup("CORP.LOCAL-S-1-5-11").unwrap()), "AUTHENTICATED USERS@CORP.LOCAL");
    // ACL edges decoded from nTSecurityDescriptor.
    assert_eq!(edges_between(g, &u(1106), &u(1108)), vec!["GenericAll"]);
    assert_eq!(edges_between(g, "CORP.LOCAL-S-1-5-32-544", D), vec!["WriteDacl", "WriteOwner"]);
    assert_eq!(edges_between(g, &u(1105), &u(1106)), vec!["AddMember"]);
    assert_eq!(edges_between(g, &u(1104), &u(1106)), vec!["AddSelf", "MemberOf"]);
    assert_eq!(edges_between(g, &u(1105), &u(1104)), vec!["ForceChangePassword"]);
    // Inherited ACE for the group class does not apply to a user; the one for users does.
    assert_eq!(edges_between(g, &u(1106), &u(1104)), vec!["WriteSPN"]);
    assert_eq!(edges_between(g, &u(1110), D), vec!["DCSync", "GetChanges", "GetChangesAll"]);
    // Replication rights split over two groups: the member completes DCSync;
    // the group with GetChanges + GetChangesInFilteredSet syncs LAPS passwords.
    assert_eq!(edges_between(g, &u(1111), D), vec!["GetChanges", "GetChangesInFilteredSet"]);
    assert_eq!(edges_between(g, &u(1112), D), vec!["GetChangesAll"]);
    assert_eq!(edges_between(g, &u(1113), D), vec!["DCSync"]);
    assert_eq!(edges_between(g, &u(1111), &u(1107)), vec!["SyncLAPSPassword"]);
    assert!(edges_between(g, &u(1113), &u(1107)).is_empty(), "DCSync holders get no SyncLAPSPassword");
    assert_eq!(edges_between(g, &u(1106), &u(1107)), vec!["ReadLAPSPassword"]);
    assert_eq!(edges_between(g, &u(1108), &u(1107)), vec!["AllowedToAct"]);
    assert_eq!(edges_between(g, &u(1108), &u(1109)), vec!["ReadGMSAPassword"]);
    assert_eq!(edges_between(g, &u(1105), &u(1107)), vec!["AllowedToDelegate"]);
    assert_eq!(edges_between(g, &u(1105), "S-1-5-21-9-9-9-1500"), vec!["HasSIDHistory"]);
    assert_eq!(edges_between(g, D, "S-1-5-21-9-9-9"), vec!["CrossForestTrust", "TrustedBy"]);
    // ADCS: chain + publication + composite edges fire from LDAP data alone.
    let eca = "00000032-0000-4000-8000-000000000032";
    assert_eq!(edges_between(g, &u(1000), eca), vec!["HostsCAService"]);
    assert_eq!(edges_between(g, "00000031-0000-4000-8000-000000000031", eca), vec!["PublishedTo"]);
    assert!(edges_between(g, &u(513), D).contains(&"ADCSESC1".to_string()));
    assert!(edges_between(g, &u(513), &u(1106)).contains(&"ADCSESC13".to_string()));
    // Properties.
    let p: serde_json::Value = serde_json::from_str(g.props(alice)).unwrap();
    assert_eq!(p["distinguishedname"], "CN=ALICE SMITH,OU=STAFF,DC=CORP,DC=LOCAL");
    assert_eq!(p["pwdlastset"], 1_705_526_400);
    assert_eq!(p["whencreated"], 1_704_164_645);
    assert!(p["description"].as_str().unwrap().ends_with("folds the line"));
    let p: serde_json::Value = serde_json::from_str(g.props(g.lookup(eca).unwrap())).unwrap();
    assert_eq!(p["unresolvedpublishedtemplates"], serde_json::json!(["Missing"]));
    assert_eq!(p["certchain"].as_array().unwrap().len(), 2);
    let t: serde_json::Value =
        serde_json::from_str(g.props(g.lookup("00000031-0000-4000-8000-000000000031").unwrap())).unwrap();
    assert_eq!(t["validityperiod"], "1 year");
    assert_eq!(t["enrolleesuppliessubject"], true);
    // The unresolvable member DN is counted, not invented.
    assert!(b.ingest.dn_edges_unresolved >= 1);
}

/// Read every entry of every fixture file back through the LDIF reader and
/// write them as one AD Explorer snapshot; the snapshot must produce the same
/// graph as the LDIF.
#[test]
fn adexplorer_snapshot_equals_ldif() {
    let dir = tmp("adx");
    let mut objects: Vec<adexplorer::testing::Object> = Vec::new();
    for f in fs::read_dir(fixture("ldif")).unwrap() {
        let p = f.unwrap().path();
        let kind = scan::detect(&p).unwrap();
        let input = ldap::open(&p, kind, &dir).unwrap().unwrap();
        for c in 0..input.chunks() {
            input.read(c, NEED_ALL, &mut |r| {
                let e = r.unwrap();
                let mut attrs: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
                for (a, v) in &e.vals {
                    let name = A::name(*a).to_string();
                    match attrs.iter_mut().find(|(n, _)| *n == name) {
                        Some((_, vs)) => vs.push(v.to_vec()),
                        None => attrs.push((name, vec![v.to_vec()])),
                    }
                }
                objects.push((e.dn.into_owned(), attrs));
            });
        }
    }
    assert!(objects.len() > 40);
    let snap_dir = dir.join("snap");
    fs::create_dir_all(&snap_dir).unwrap();
    let snap = snap_dir.join("corp.dat");
    adexplorer::testing::write(&snap, "dc01.corp.local", &objects).unwrap();
    assert_eq!(scan::detect(&snap), Some(scan::InputKind::AdExplorer));

    let a = build(&snap_dir);
    let l = build(&fixture("ldif"));
    assert_eq!(a.ingest.records, objects.len() as u64);
    assert_same(&a.graph, &l.graph);
    // Snapshot values are converted to LDAP text: properties match too.
    let alice = a.graph.lookup(&format!("{D}-1104")).unwrap();
    let la = l.graph.lookup(&format!("{D}-1104")).unwrap();
    assert_eq!(a.graph.props(alice), l.graph.props(la));
    drop(a);
    let _ = fs::remove_dir_all(&dir);
}

/// LDIF inside a zip (as uploaded to the server) is detected and ingested.
#[test]
fn ldif_inside_zip() {
    let dir = tmp("zip");
    let z = dir.join("dump.zip");
    {
        let f = fs::File::create(&z).unwrap();
        let mut w = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for name in ["corp-domain.ldif", "corp-config.ldf", "corp-schema.ldif.gz"] {
            w.start_file(format!("nested/{name}"), opts).unwrap();
            std::io::Write::write_all(&mut w, &fs::read(fixture("ldif").join(name)).unwrap()).unwrap();
        }
        w.finish().unwrap();
    }
    let zb = build(&z);
    let l = build(&fixture("ldif"));
    assert_eq!(zb.ingest.zip_entries, 3);
    assert_same(&zb.graph, &l.graph);
    drop(zb);
    let _ = fs::remove_dir_all(&dir);
}
