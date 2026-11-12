//! OT findings (docs/OT.md): items, and impact measured against OT
//! controllers instead of Tier Zero.

use ch_analysis::findings::{evaluate, FindingResult, Items, CATALOG, OT_CONTROLLERS, TIER0_LABEL};
use ch_ingest::{build_graph, IngestOptions};
use ch_model::flags;
use ch_store::Graph;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-4-5-6";

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn write(d: &Path, file: &str, ty: &str, data: Value) {
    let body = json!({"data": data, "meta": {"type": ty, "count": 1, "version": 6}});
    fs::write(d.join(file), body.to_string()).unwrap();
}

fn sid(rid: u32) -> String {
    format!("{D}-{rid}")
}

fn local(slot: &[(&str, &str)]) -> Value {
    json!({"Collected": true, "Results": slot.iter().map(|(id, t)| json!({"ObjectIdentifier": id, "ObjectType": t})).collect::<Vec<_>>()})
}

fn fixture(d: &Path, with_ot: bool) {
    let (bob, carol, it_wks, ot_eng, du, da) = (sid(1101), sid(1102), sid(2001), sid(2002), sid(513), sid(512));
    let (ews, hmi, hist) = (sid(1201), sid(1202), sid(1203));
    write(d, "a_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL"}, "Aces": []}]));
    let user = |id: &str, name: &str| {
        json!({"ObjectIdentifier": id, "Properties": {"name": name, "enabled": true, "domainsid": D}, "PrimaryGroupSID": du, "Aces": []})
    };
    write(d, "a_users.json", "users", json!([user(&bob, "BOB@CORP.LOCAL"), user(&carol, "CAROL@CORP.LOCAL")]));
    let group = |id: &str, name: &str, members: &[&str]| {
        json!({"ObjectIdentifier": id, "Properties": {"name": name},
               "Members": members.iter().map(|m| json!({"ObjectIdentifier": m, "ObjectType": "User"})).collect::<Vec<_>>(), "Aces": []})
    };
    write(
        d,
        "a_groups.json",
        "groups",
        json!([
            group(&it_wks, "IT-WKS@CORP.LOCAL", &[&bob]),
            group(&ot_eng, "OT-ENG@CORP.LOCAL", &[&carol]),
            group(&du, "DOMAIN USERS@CORP.LOCAL", &[]),
            group(&da, "DOMAIN ADMINS@CORP.LOCAL", &[])
        ]),
    );
    let computer = |id: &str, name: &str, os: &str, admins: Value, rdp: Value| {
        json!({"ObjectIdentifier": id, "Properties": {"name": name, "enabled": true, "operatingsystem": os, "haslaps": false, "domainsid": D},
               "PrimaryGroupSID": sid(515), "Aces": [], "LocalAdmins": admins, "RemoteDesktopUsers": rdp})
    };
    write(
        d,
        "a_computers.json",
        "computers",
        json!([
            computer(&ews, "EWS1.CORP.LOCAL", "Windows 10 Enterprise LTSC", local(&[(&it_wks, "Group"), (&ot_eng, "Group"), (&da, "Group")]), local(&[])),
            computer(&hmi, "HMI1.CORP.LOCAL", "Windows 10 IoT Enterprise", local(&[(&ot_eng, "Group")]), local(&[(&du, "Group")])),
            computer(&hist, "HIST1.CORP.LOCAL", "Windows Server 2012 R2 Standard", local(&[(&ot_eng, "Group")]), local(&[]))
        ]),
    );
    if with_ot {
        let og = json!({"metadata": {"source_kind": "OTInventory"}, "graph": {
            "nodes": [
                {"id": ews, "kinds": ["Computer"], "properties": {"purdue_level": 2, "ot_role": "EWS"}},
                {"id": hmi, "kinds": ["Computer"], "properties": {"purdue_level": 2, "ot_role": "HMI"}},
                {"id": hist, "kinds": ["Computer"], "properties": {"purdue_level": 3, "ot_role": "Historian"}},
                {"id": carol, "kinds": ["User"], "properties": {"ot_role": "OTUser"}},
                {"id": ot_eng, "kinds": ["Group"], "properties": {"ot_role": "OTGroup"}},
                {"id": "plc-1", "kinds": ["PLC"], "properties": {"name": "PLC-1", "purdue_level": 1, "ot_role": "PLC", "fix_cost": "Fixed"}},
                {"id": hist, "kinds": ["Computer"], "properties": {"fix_cost": "window"}}
            ],
            "edges": [{"kind": "CanProgram", "start": {"value": ews}, "end": {"value": "plc-1"}}]}});
        fs::write(d.join("z_ot.json"), og.to_string()).unwrap();
    }
}

fn graph(name: &str, with_ot: bool) -> (PathBuf, Graph) {
    let d = dir(name);
    fixture(&d, with_ot);
    let g = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap().graph;
    (d, g)
}

fn find<'a>(res: &'a [FindingResult], id: &str) -> Option<&'a FindingResult> {
    res.iter().find(|f| f.def.id == id)
}

fn items(g: &Graph, f: &FindingResult) -> Vec<String> {
    let mut v: Vec<String> = match &f.items {
        Items::Edges(es) => es.iter().map(|&(s, d, k)| format!("{} -{}-> {}", g.name(s), g.edge_kind_name(k), g.name(d))).collect(),
        Items::Nodes(ns) => ns.iter().map(|&n| g.name(n).to_string()).collect(),
    };
    v.sort();
    v
}

#[test]
fn ot_findings_measured_against_controllers() {
    let (d, g) = graph("ot-findings", true);
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let res = evaluate(&g, &tier0, &ch_query::Cancel::never(), &|_, _| {});

    // OT-ENG (ot_role) and Domain Admins (Tier Zero) are not IT findings.
    let ews = find(&res, "ot-ews-it-access").expect("ot-ews-it-access");
    assert_eq!(items(&g, ews), ["IT-WKS@CORP.LOCAL -AdminTo-> EWS1.CORP.LOCAL"]);
    let e = ews.exposure.as_ref().expect("measured");
    assert_eq!(e.target, OT_CONTROLLERS.label);
    // BOB and IT-WKS reach PLC-1 only through this edge.
    assert!(e.principals_cut >= 1, "{e:?}");

    let remote = find(&res, "ot-it-remote-access").expect("ot-it-remote-access");
    assert_eq!(items(&g, remote), ["DOMAIN USERS@CORP.LOCAL -CanRDP-> HMI1.CORP.LOCAL"]);
    let e = remote.exposure.as_ref().expect("measured");
    assert_eq!(e.principals_cut, 0, "the HMI does not lead to a controller: {e:?}");

    assert_eq!(items(&g, find(&res, "ot-legacy-os").unwrap()), ["HIST1.CORP.LOCAL"]);
    assert_eq!(items(&g, find(&res, "ot-no-laps").unwrap()), ["EWS1.CORP.LOCAL", "HIST1.CORP.LOCAL", "HMI1.CORP.LOCAL"]);
    assert!(find(&res, "ot-vendor-accounts").is_none());

    // Other findings keep measuring against Tier Zero.
    for f in res.iter().filter(|f| f.def.category != "OT") {
        if let Some(e) = &f.exposure {
            assert_eq!(e.target, TIER0_LABEL, "{}", f.def.id);
        }
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn no_ot_findings_without_ot_data() {
    let (d, g) = graph("ot-findings-none", false);
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let res = evaluate(&g, &tier0, &ch_query::Cancel::never(), &|_, _| {});
    let ot: Vec<&str> = res.iter().filter(|f| f.def.category == "OT").map(|f| f.def.id).collect();
    assert!(ot.is_empty(), "{ot:?}");
    assert!(CATALOG.iter().filter(|d| d.category == "OT").all(|d| d.mitre.iter().all(|m| m.starts_with("T0"))));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn fix_costs_from_properties() {
    use ch_analysis::simulate::{fix_costs, FixCost};
    let (d, g) = graph("ot-fix-costs", true);
    let cost = fix_costs(&g).expect("fix_cost properties present");
    assert_eq!(cost[g.lookup("plc-1").unwrap() as usize], FixCost::Fixed as u8, "case-insensitive");
    assert_eq!(cost[g.lookup(&sid(1203)).unwrap() as usize], FixCost::Window as u8);
    assert_eq!(cost[g.lookup(&sid(1201)).unwrap() as usize], FixCost::Live as u8);
    let (d2, g2) = graph("ot-fix-costs-none", false);
    assert!(fix_costs(&g2).is_none());
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&d2);
}
