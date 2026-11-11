//! Collection-aware merging (`ch_ingest::merge`): several dumps of the same
//! directory over time, different collectors for one domain, disjoint
//! domains, hybrid AD + Azure, LDIF ranged `member` reads, and equivalence
//! with the `union` policy wherever no object is described twice.

use ch_ingest::{build_graph, Built, IngestOptions, MergePolicy};
use ch_model::flags;
use ch_store::Graph;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-5-6-7";
const OLD: &str = "20240101000000";
const NEW: &str = "20240201000000";
const T: &str = "99999999-2222-3333-4444-555555555555";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-merge-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn write(d: &Path, file: &str, ty: &str, data: Value) {
    let body = json!({"data": data, "meta": {"type": ty, "count": 1, "version": 6}});
    fs::write(d.join(file), body.to_string()).unwrap();
}

fn build(inputs: &[PathBuf], policy: MergePolicy, window_secs: u64) -> Built {
    let opts = IngestOptions { merge_policy: policy, session_window_secs: window_secs, ..Default::default() };
    let b = build_graph(inputs, &opts).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    b
}

fn id(g: &Graph, oid: &str) -> u32 {
    g.lookup(oid).unwrap_or_else(|| panic!("no node {oid}"))
}

fn has_edge(g: &Graph, from: &str, to: &str, kind: &str) -> bool {
    let (Some(f), Some(t)) = (g.lookup(from), g.lookup(to)) else { return false };
    let (ds, ks) = g.out_edges(f);
    ds.iter().zip(ks).any(|(d, k)| *d == t && g.edge_kind_name(*k) == kind)
}

fn props(g: &Graph, oid: &str) -> Value {
    serde_json::from_str(g.props(id(g, oid))).unwrap_or(Value::Null)
}

fn sid(rid: u32) -> String {
    format!("{D}-{rid}")
}

fn user(rid: u32, extra: Value, aces: Value) -> Value {
    let mut p = json!({"name": format!("U{rid}@CORP.LOCAL"), "domain": "CORP.LOCAL", "domainsid": D, "enabled": true});
    p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    json!({"ObjectIdentifier": sid(rid), "Properties": p, "PrimaryGroupSID": sid(513), "Aces": aces})
}

fn ace(rid: u32, right: &str) -> Value {
    json!({"PrincipalSID": sid(rid), "PrincipalType": "User", "RightName": right})
}

fn member(rid: u32) -> Value {
    json!({"ObjectIdentifier": sid(rid), "ObjectType": "User"})
}

fn computer(rid: u32, extra: Value) -> Value {
    let mut c = json!({"ObjectIdentifier": sid(rid), "PrimaryGroupSID": sid(515), "Aces": [],
        "Properties": {"name": format!("C{rid}.CORP.LOCAL"), "domain": "CORP.LOCAL", "enabled": true}});
    c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    c
}

fn sessions(collected: bool, users: &[u32], comp: u32) -> Value {
    let r: Vec<Value> = users.iter().map(|u| json!({"UserSID": sid(*u), "ComputerSID": sid(comp)})).collect();
    json!({"Collected": collected, "FailureReason": null, "Results": r})
}

/// Older and newer SharpHound collection of CORP.LOCAL.
fn two_collections(root: &Path) -> (PathBuf, PathBuf) {
    let old = root.join("old");
    let new = root.join("new");
    fs::create_dir_all(&old).unwrap();
    fs::create_dir_all(&new).unwrap();
    let domain = json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL", "domain": "CORP.LOCAL"}, "Aces": [], "Trusts": []}]);
    write(&old, &format!("{OLD}_domains.json"), "domains", domain.clone());
    write(&new, &format!("{NEW}_domains.json"), "domains", domain);

    write(&old, &format!("{OLD}_users.json"), "users", json!([
        user(1101, json!({"description": "old", "title": "only-old"}), json!([ace(1102, "GenericAll")])),
        user(1102, json!({}), json!([])),
        // Only in the older collection: its edges are untouched.
        user(1103, json!({}), json!([ace(1102, "GenericWrite")])),
    ]));
    write(&new, &format!("{NEW}_users.json"), "users", json!([
        user(1101, json!({"description": "new", "enabled": false}), json!([])),
        user(1102, json!({}), json!([])),
    ]));
    write(&old, &format!("{OLD}_groups.json"), "groups", json!([
        {"ObjectIdentifier": sid(2001), "Properties": {"name": "G@CORP.LOCAL"}, "Members": [member(1101), member(1102)], "Aces": []}
    ]));
    write(&new, &format!("{NEW}_groups.json"), "groups", json!([
        {"ObjectIdentifier": sid(2001), "Properties": {"name": "G@CORP.LOCAL"}, "Members": [member(1101)], "Aces": []}
    ]));
    write(&old, &format!("{OLD}_computers.json"), "computers", json!([
        computer(3001, json!({"Sessions": sessions(true, &[1102], 3001),
            "LocalAdmins": {"Collected": true, "Results": [member(1102)]}})),
        computer(3002, json!({"Sessions": sessions(true, &[1101], 3002)})),
    ]));
    write(&new, &format!("{NEW}_computers.json"), "computers", json!([
        computer(3001, json!({"Sessions": sessions(true, &[1101], 3001),
            "LocalAdmins": {"Collected": false, "Results": []}})),
        // Session collection failed: older sessions stay.
        computer(3002, json!({"Sessions": sessions(false, &[], 3002)})),
    ]));
    (old, new)
}

#[test]
fn newest_collection_wins() {
    let root = tmp("two");
    let (old, new) = two_collections(&root);
    let b = build(&[old.clone(), new.clone()], MergePolicy::Newest, 0);
    let g = &b.graph;

    // Removed ACE / member / session are gone; current ones stay.
    assert!(!has_edge(g, &sid(1102), &sid(1101), "GenericAll"), "ACE removed in newer collection");
    assert!(!has_edge(g, &sid(1102), &sid(2001), "MemberOf"), "member removed in newer collection");
    assert!(has_edge(g, &sid(1101), &sid(2001), "MemberOf"));
    assert!(!has_edge(g, &sid(3001), &sid(1102), "HasSession"), "session gone in newer collection");
    assert!(has_edge(g, &sid(3001), &sid(1101), "HasSession"));
    // Edges of objects only the older collection describes are untouched.
    assert!(has_edge(g, &sid(1102), &sid(1103), "GenericWrite"));
    // Not collected in the newer collection: older data stays.
    assert!(has_edge(g, &sid(1102), &sid(3001), "AdminTo"));
    assert!(has_edge(g, &sid(3002), &sid(1101), "HasSession"));
    // Primary group edges are re-emitted by both: kept.
    assert!(has_edge(g, &sid(1101), &sid(513), "MemberOf"));

    // Properties: newest value per key, older-only keys kept, provenance.
    let p = props(g, &sid(1101));
    assert_eq!(p["description"], "new");
    assert_eq!(p["title"], "only-old");
    assert!(!g.has_flag(id(g, &sid(1101)), flags::ENABLED), "flags come from the newest record");
    let srcs = &b.ingest.sources;
    let file_of = |i: &Value| srcs[i.as_u64().unwrap() as usize].file.clone();
    let listed: Vec<String> = p["_sources"].as_array().unwrap().iter().map(file_of).collect();
    assert_eq!(listed, vec![format!("{NEW}_users.json"), format!("{OLD}_users.json")]);
    // Single-source nodes carry no provenance property.
    assert!(props(g, &sid(1103)).get("_sources").is_none());

    // Manifest.
    assert_eq!(b.ingest.merge_policy, "newest");
    // Edge records of superseded data, including ones the newer records restate.
    assert_eq!(b.ingest.superseded_edges, 8, "{srcs:#?}");
    let old_users = srcs.iter().find(|s| s.file == format!("{OLD}_users.json")).unwrap();
    assert_eq!(old_users.collected_at.as_deref(), Some("2024-01-01T00:00:00Z"));
    assert_eq!(old_users.collected_at_source, Some("filename"));
    assert_eq!(old_users.format, "sharphound");
    assert_eq!(old_users.objects, 3);
    assert_eq!(old_users.superseded_objects, 2);
    assert_eq!(old_users.superseded_edges, 3);
    assert_eq!(old_users.domains, vec!["CORP.LOCAL".to_string()]);
    let meta = g.meta().ingest.as_ref().unwrap();
    assert_eq!(meta["merge_policy"], "newest");
    assert_eq!(meta["sources"].as_array().unwrap().len(), srcs.len());

    // Order of inputs does not matter.
    let b2 = build(&[new.clone(), old.clone()], MergePolicy::Newest, 0);
    // (Source ids in `_sources` follow input order.)
    assert_eq!(snapshot(&b2.graph, true), snapshot(g, true));

    // Session window: sessions of an older collection within the window stay.
    let w = build(&[old.clone(), new.clone()], MergePolicy::Newest, 40 * 86_400);
    assert!(has_edge(&w.graph, &sid(3001), &sid(1102), "HasSession"));
    assert!(!has_edge(&w.graph, &sid(1102), &sid(1101), "GenericAll"), "the window only applies to sessions");
    let w = build(&[old.clone(), new.clone()], MergePolicy::Newest, 20 * 86_400);
    assert!(!has_edge(&w.graph, &sid(3001), &sid(1102), "HasSession"));

    // `union`: the old behaviour.
    let u = build(&[old, new], MergePolicy::Union, 0);
    let g = &u.graph;
    assert!(has_edge(g, &sid(1102), &sid(1101), "GenericAll"));
    assert!(has_edge(g, &sid(1102), &sid(2001), "MemberOf"));
    assert!(has_edge(g, &sid(3001), &sid(1102), "HasSession"));
    assert!(g.has_flag(id(g, &sid(1101)), flags::ENABLED), "union ORs flags");
    assert!(props(g, &sid(1101)).get("_sources").is_none());
    assert_eq!(u.ingest.superseded_edges, 0);
    // Exactly the three removed relationships differ from the union.
    let removed: BTreeSet<_> = snapshot(g, false).1.difference(&snapshot(&b.graph, false).1).cloned().collect();
    let e = |a: u32, b: u32, k: &str| (sid(a), sid(b), k.to_string());
    let expected: BTreeSet<_> = [e(1102, 1101, "GenericAll"), e(1102, 2001, "MemberOf"), e(3001, 1102, "HasSession")].into();
    assert_eq!(removed, expected);
    assert!(snapshot(&b.graph, false).1.is_subset(&snapshot(g, false).1));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn undated_collections_merge_as_union() {
    // Without collection times, ordering is never guessed.
    let root = tmp("undated");
    let (old, new) = two_collections(&root);
    for d in [&old, &new] {
        for e in fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let undated = name.split_once('_').unwrap().1.to_string();
            fs::rename(&p, d.join(format!("{}_{undated}", if d == &old { "a" } else { "b" }))).unwrap();
        }
    }
    let n = build(&[old.clone(), new.clone()], MergePolicy::Newest, 0);
    let u = build(&[old, new], MergePolicy::Union, 0);
    assert!(n.ingest.sources.iter().all(|s| s.collected_at.is_none()));
    assert_eq!(n.ingest.superseded_edges, 0);
    assert!(has_edge(&n.graph, &sid(1102), &sid(1101), "GenericAll"));
    assert_eq!(snapshot(&n.graph, true), snapshot(&u.graph, true));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn different_collectors_same_domain() {
    // Older SharpHound, newer ldapdomaindump of the same group.
    let root = tmp("collectors");
    let (old, _) = two_collections(&root);
    let ldd = root.join("ldd");
    fs::create_dir_all(&ldd).unwrap();
    let dn = |cn: &str| format!("CN={cn},CN=Users,DC=corp,DC=local");
    fs::write(
        ldd.join("20240301000000_domain_users.json"),
        json!([{"attributes": {"objectClass": ["user"], "sAMAccountName": ["U1101"], "distinguishedName": [dn("U1101")],
            "objectSid": [sid(1101)], "userAccountControl": [512], "description": ["from ldd"]}}])
        .to_string(),
    )
    .unwrap();
    fs::write(
        ldd.join("20240301000000_domain_groups.json"),
        json!([{"attributes": {"objectClass": ["group"], "sAMAccountName": ["G"], "distinguishedName": [dn("G")],
            "objectSid": [sid(2001)], "member": [dn("U1101")]}}])
        .to_string(),
    )
    .unwrap();
    let b = build(&[old, ldd], MergePolicy::Newest, 0);
    let g = &b.graph;
    assert!(has_edge(g, &sid(1101), &sid(2001), "MemberOf"));
    assert!(!has_edge(g, &sid(1102), &sid(2001), "MemberOf"), "newer ldapdomaindump membership wins");
    let p = props(g, &sid(1101));
    assert_eq!(p["description"], "from ldd");
    assert_eq!(p["title"], "only-old", "keys only the older collector wrote are kept");
    // SharpHound ACEs on U1101 are not claimed by ldapdomaindump (no ACL data): kept.
    assert!(has_edge(g, &sid(1102), &sid(1101), "GenericAll"));
    let _ = fs::remove_dir_all(&root);
}

/// Hybrid AD (older) + Azure (newer) still link.
#[test]
fn ad_and_azure_link_across_collections() {
    let root = tmp("hybrid");
    let (old, _) = two_collections(&root);
    let az = root.join("az");
    fs::create_dir_all(&az).unwrap();
    let items = json!([
        {"kind": "AZTenant", "data": {"tenantId": T, "displayName": "CORP"}},
        {"kind": "AZUser", "data": {"id": "az-u1", "userPrincipalName": "u1@corp.com", "accountEnabled": true, "tenantId": T,
            "tenantName": "CORP", "onPremisesSecurityIdentifier": sid(1101), "onPremisesSyncEnabled": true}}
    ]);
    fs::write(az.join("20240315000000_azurehound.json"), json!({"data": items, "meta": {"type": "azure", "version": 5}}).to_string())
        .unwrap();
    let b = build(&[old, az], MergePolicy::Newest, 0);
    assert!(has_edge(&b.graph, &sid(1101), "AZ-U1", "SyncedToEntraUser"));
    let azs = b.ingest.sources.iter().find(|s| s.format == "azurehound").unwrap();
    assert_eq!(azs.domains, vec![T.to_ascii_uppercase()]);
    assert_eq!(azs.collected_at_source, Some("filename"));
    let _ = fs::remove_dir_all(&root);
}

/// Every node (oid, kind, name, flags, properties) and edge of a graph.
type Snapshot = (BTreeMap<String, (u8, String, u32, String)>, BTreeSet<(String, String, String)>);

fn snapshot(g: &Graph, strip_sources: bool) -> Snapshot {
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeSet::new();
    for i in 0..g.node_count() as u32 {
        let mut p = g.props(i).to_string();
        if strip_sources && p.contains("\"_sources\"") {
            let mut v: serde_json::Map<String, Value> = serde_json::from_str(&p).unwrap();
            v.remove("_sources");
            p = Value::Object(v).to_string();
        }
        nodes.insert(g.oid(i).to_string(), (g.kind(i) as u8, g.name(i).to_string(), g.flags(i), p));
        let (ds, ks) = g.out_edges(i);
        for (&d, &k) in ds.iter().zip(ks) {
            edges.insert((g.oid(i).to_string(), g.oid(d).to_string(), g.edge_kind_name(k).to_string()));
        }
    }
    (nodes, edges)
}

fn assert_policies_equal(name: &str, inputs: &[PathBuf]) {
    let n = build(inputs, MergePolicy::Newest, 0);
    let u = build(inputs, MergePolicy::Union, 0);
    let (sn, su) = (snapshot(&n.graph, false), snapshot(&u.graph, false));
    assert_eq!(n.ingest.superseded_edges, 0, "{name}");
    assert_eq!(n.ingest.superseded_objects, 0, "{name}");
    let only_n: Vec<_> = sn.1.difference(&su.1).take(10).collect();
    let only_u: Vec<_> = su.1.difference(&sn.1).take(10).collect();
    assert!(sn.1 == su.1, "{name}: edge sets differ\nonly newest: {only_n:#?}\nonly union: {only_u:#?}");
    let diff: Vec<_> = sn.0.iter().filter(|(k, v)| su.0.get(*k) != Some(*v)).take(5).collect();
    assert!(sn.0 == su.0, "{name}: nodes differ: {diff:#?}");
    assert!(sn.0.len() > 10 && sn.1.len() > 10, "{name}: not vacuous");
}

/// Copy every file of `src` into `dst` with a `YYYYMMDDHHMMSS_` prefix.
fn copy_dated(src: &Path, dst: &Path, stamp: &str) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let p = e.unwrap().path();
        fs::copy(&p, dst.join(format!("{stamp}_{}", p.file_name().unwrap().to_string_lossy()))).unwrap();
    }
}

fn corp(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corp").join(sub)
}

/// With one source per object (a single collection, or disjoint domains /
/// tenants) both policies build exactly the same graph.
#[test]
fn single_and_disjoint_sources_equal_union() {
    let root = tmp("equiv");
    // Single collections: SharpHound (undated and dated), LDIF (dated by
    // whenChanged), synthetic SharpHound + AzureHound, synthetic LDIF.
    assert_policies_equal("corp sharphound", &[corp("sharphound")]);
    let dated = root.join("corp-dated");
    copy_dated(&corp("sharphound"), &dated, "20250101000000");
    assert_policies_equal("corp sharphound dated", std::slice::from_ref(&dated));
    assert_policies_equal("corp ldif", &[corp("ldif")]);
    let synth = root.join("synth");
    let cfg = ch_synth::SynthConfig { users: 600, computers: 150, groups: 80, seed: 3 };
    ch_synth::generate(&cfg, &synth).unwrap();
    assert_policies_equal("synth sharphound+azurehound", std::slice::from_ref(&synth));
    let synth_ldif = root.join("synth.ldif");
    ch_synth::generate_ldif(&cfg, &synth_ldif).unwrap();
    assert_policies_equal("synth ldif", std::slice::from_ref(&synth_ldif));
    // Hybrid single collection: AD + Azure.
    let (old, _) = two_collections(&root.join("two"));
    // Disjoint domains / tenants, different collection times: CORP (corp
    // fixture), SYNTH.LOCAL + its tenant, CORP.LOCAL (S-1-5-21-5-6-7).
    let synth_dated = root.join("synth-dated");
    copy_dated(&synth, &synth_dated, "20250301000000");
    assert_policies_equal("disjoint", &[dated.clone(), synth_dated.clone(), old.clone()]);
    // Different collectors for disjoint domains: corp LDIF + synth JSON.
    assert_policies_equal("disjoint mixed", &[corp("ldif"), synth_dated, old]);
    let _ = fs::remove_dir_all(&root);
}

/// The same collection ingested twice (e.g. re-uploaded under another name):
/// identical to ingesting it once apart from `_sources`.
#[test]
fn duplicate_collection_is_idempotent() {
    let root = tmp("dup");
    let a = root.join("a");
    let b = root.join("b");
    copy_dated(&corp("sharphound"), &a, "20250101000000");
    copy_dated(&corp("sharphound"), &b, "20250201000000");
    let once = build(std::slice::from_ref(&a), MergePolicy::Newest, 0);
    let twice = build(&[a, b], MergePolicy::Newest, 0);
    assert!(twice.ingest.superseded_edges > 0);
    let (n1, e1) = snapshot(&once.graph, true);
    let (n2, e2) = snapshot(&twice.graph, true);
    assert!(e1 == e2, "edges differ: {:?}", e1.symmetric_difference(&e2).take(5).collect::<Vec<_>>());
    let canon = |m: BTreeMap<String, (u8, String, u32, String)>| -> BTreeMap<String, (u8, String, u32, Value)> {
        m.into_iter().map(|(k, (a, b, c, p))| (k, (a, b, c, serde_json::from_str(&p).unwrap_or(Value::Null)))).collect()
    };
    assert!(canon(n1) == canon(n2));
    let _ = fs::remove_dir_all(&root);
}

// ------------------------------------------------------------------ LDIF

fn sid_b64(s: &str) -> String {
    let parts: Vec<u64> = s.trim_start_matches("S-").split('-').map(|x| x.parse().unwrap()).collect();
    let mut b = vec![parts[0] as u8, (parts.len() - 2) as u8];
    b.extend_from_slice(&parts[1].to_be_bytes()[2..]);
    for sa in &parts[2..] {
        b.extend_from_slice(&(*sa as u32).to_le_bytes());
    }
    b64(&b)
}

fn b64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

fn ldif_user(cn: &str, rid: u32, changed: &str) -> String {
    format!(
        "dn: CN={cn},CN=Users,DC=corp,DC=local\nobjectClass: top\nobjectClass: user\nobjectSid:: {}\nsAMAccountName: {cn}\nuserAccountControl: 512\nwhenChanged: {changed}\n\n",
        sid_b64(&sid(rid))
    )
}

fn ldif_head(changed: &str) -> String {
    let mut s = format!("version: 1\n\ndn: DC=corp,DC=local\nobjectClass: top\nobjectClass: domainDNS\nobjectSid:: {}\nwhenChanged: {changed}\n\n", sid_b64(D));
    for (cn, rid) in [("alice", 1101), ("bob", 1102), ("carol", 1103), ("dave", 1104), ("erin", 1105)] {
        s.push_str(&ldif_user(cn, rid, changed));
    }
    s
}

const BIG: &str = "CN=Big,CN=Users,DC=corp,DC=local";

fn big_group(changed: &str, members: &str) -> String {
    format!(
        "dn: {BIG}\nobjectClass: top\nobjectClass: group\nobjectSid:: {}\nsAMAccountName: Big\nwhenChanged: {changed}\n{members}\n",
        sid_b64(&sid(2001))
    )
}

fn m(cn: &str, opt: &str) -> String {
    format!("member{opt}: CN={cn},CN=Users,DC=corp,DC=local\n")
}

#[test]
fn ldif_member_ranges_union() {
    let root = tmp("ranges");
    let t = "20240101000000.0Z";
    // First range in the dump, a continuation entry in the same file, and the
    // remaining range in a separate file (as written by tools/ldap-member-ranges).
    let main = format!(
        "{}{}dn: {BIG}\nmember;range=2-3: CN=carol,CN=Users,DC=corp,DC=local\nmember;range=2-3: CN=dave,CN=Users,DC=corp,DC=local\n\n",
        ldif_head(t),
        big_group(t, &(m("alice", ";range=0-1") + &m("bob", ";range=0-1")))
    );
    fs::write(root.join("corp.ldif"), main).unwrap();
    fs::write(root.join("corp-member-ranges.ldif"), format!("# ranges\ndn: {BIG}\n{}\n", m("erin", ";range=4-*"))).unwrap();
    let b = build(std::slice::from_ref(&root), MergePolicy::Newest, 0);
    let g = &b.graph;
    for rid in 1101..=1105 {
        assert!(has_edge(g, &sid(rid), &sid(2001), "MemberOf"), "member {rid}");
    }
    // Continuation entries never replace the group's own record.
    assert_eq!(g.name(id(g, &sid(2001))), "BIG@CORP.LOCAL");
    assert_eq!(props(g, &sid(2001))["samaccountname"], "Big");
    let srcs = &b.ingest.sources;
    let main_src = srcs.iter().find(|s| s.file == "corp.ldif").unwrap();
    assert_eq!(main_src.collected_at_source, Some("whenchanged"));
    assert_eq!(main_src.format, "ldif");
    assert_eq!(main_src.domains, vec!["CORP.LOCAL".to_string()]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn ldif_newer_dump_supersedes_membership() {
    let root = tmp("ldifnew");
    let (t1, t2) = ("20240101000000.0Z", "20240201000000.0Z");
    fs::write(root.join("old.ldif"), ldif_head(t1) + &big_group(t1, &(m("alice", "") + &m("bob", "")))).unwrap();
    fs::write(root.join("new.ldif"), ldif_head(t2) + &big_group(t2, &m("alice", ";range=0-*"))).unwrap();
    let b = build(std::slice::from_ref(&root), MergePolicy::Newest, 0);
    assert!(has_edge(&b.graph, &sid(1101), &sid(2001), "MemberOf"));
    assert!(!has_edge(&b.graph, &sid(1102), &sid(2001), "MemberOf"), "bob removed in the newer dump");
    let u = build(std::slice::from_ref(&root), MergePolicy::Union, 0);
    assert!(has_edge(&u.graph, &sid(1102), &sid(2001), "MemberOf"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn adexplorer_snapshot_time_orders_snapshots() {
    use ch_ingest::ldap::adexplorer::testing;
    let root = tmp("adx");
    let sidb = |s: &str| ch_ingest::ldap::sd::sid_bytes(s).unwrap();
    let user = |cn: &str, rid: u32| -> testing::Object {
        (
            format!("CN={cn},CN=Users,DC=corp,DC=local"),
            vec![
                ("objectClass".into(), vec![b"top".to_vec(), b"user".to_vec()]),
                ("objectSid".into(), vec![sidb(&sid(rid))]),
                ("sAMAccountName".into(), vec![cn.as_bytes().to_vec()]),
            ],
        )
    };
    let snapshot = |file: &str, members: &[&str], filetime: u64| {
        let objs: Vec<testing::Object> = vec![
            ("DC=corp,DC=local".into(), vec![("objectClass".into(), vec![b"domainDNS".to_vec()]), ("objectSid".into(), vec![sidb(D)])]),
            user("alice", 1101),
            user("bob", 1102),
            (
                BIG.into(),
                vec![
                    ("objectClass".into(), vec![b"group".to_vec()]),
                    ("objectSid".into(), vec![sidb(&sid(2001))]),
                    ("sAMAccountName".into(), vec![b"Big".to_vec()]),
                    ("member".into(), members.iter().map(|m| format!("CN={m},CN=Users,DC=corp,DC=local").into_bytes()).collect()),
                ],
            ),
        ];
        let p = root.join(file);
        testing::write(&p, "dc01.corp.local", &objs).unwrap();
        let mut b = fs::read(&p).unwrap();
        b[0x0e..0x16].copy_from_slice(&filetime.to_le_bytes());
        fs::write(&p, b).unwrap();
    };
    // FILETIMEs of 2024-02-01 and 2024-01-01; the newer snapshot sorts first.
    let ft = |unix: u64| (unix + 11_644_473_600) * 10_000_000;
    snapshot("a.dat", &["alice"], ft(1_706_745_600));
    snapshot("b.dat", &["alice", "bob"], ft(1_704_067_200));
    let b = build(std::slice::from_ref(&root), MergePolicy::Newest, 0);
    assert!(has_edge(&b.graph, &sid(1101), &sid(2001), "MemberOf"));
    assert!(!has_edge(&b.graph, &sid(1102), &sid(2001), "MemberOf"), "bob removed in the newer snapshot");
    let a = b.ingest.sources.iter().find(|s| s.file == "a.dat").unwrap();
    assert_eq!((a.format, a.collected_at_source), ("adexplorer", Some("snapshot")));
    assert_eq!(a.collected_at.as_deref(), Some("2024-02-01T00:00:00Z"));
    let _ = fs::remove_dir_all(&root);
}
