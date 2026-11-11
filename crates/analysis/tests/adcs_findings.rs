//! ADCS findings without composite edges: ESC2 (Any Purpose / no EKU),
//! ESC5 (PKI object control) and ESC15 (schema v1 + supplied subject).

use ch_analysis::findings::CATALOG;
use ch_ingest::{build_graph, IngestOptions};
use ch_store::Graph;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-7-8-9";

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn write(d: &Path, file: &str, ty: &str, data: serde_json::Value) {
    let body = json!({"data": data, "meta": {"type": ty, "count": 1, "version": 6}});
    fs::write(d.join(file), body.to_string()).unwrap();
}

fn fixture(d: &Path) {
    let du = format!("{D}-513");
    write(d, "a_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL"}, "Aces": []}]));
    write(
        d,
        "a_users.json",
        "users",
        json!([{"ObjectIdentifier": format!("{D}-1104"), "Properties": {"name": "ALICE@CORP.LOCAL", "enabled": true, "domainsid": D}, "PrimaryGroupSID": du, "Aces": []}]),
    );
    write(
        d,
        "a_groups.json",
        "groups",
        json!([{"ObjectIdentifier": du, "Properties": {"name": "DOMAIN USERS@CORP.LOCAL"}, "Members": [], "Aces": []}]),
    );
    write(
        d,
        "a_computers.json",
        "computers",
        json!([{"ObjectIdentifier": format!("{D}-1105"), "Properties": {"name": "CA01.CORP.LOCAL", "enabled": true}, "PrimaryGroupSID": format!("{D}-515")}]),
    );
    let alice = format!("{D}-1104");
    write(d, "a_ntauthstores.json", "ntauthstores", json!([{"ObjectIdentifier": "N-1", "DomainSID": D,
        "Properties": {"name": "NTAUTHCERTIFICATES@CORP.LOCAL", "certthumbprints": ["BB"], "domainsid": D},
        "Aces": [{"PrincipalSID": alice, "PrincipalType": "User", "RightName": "GenericWrite", "IsInherited": false}]}]));
    write(d, "a_rootcas.json", "rootcas", json!([{"ObjectIdentifier": "R-1", "DomainSID": D,
        "Properties": {"name": "ROOT@CORP.LOCAL", "certthumbprint": "AA", "certchain": ["AA"], "domainsid": D}, "Aces": []}]));
    let published: Vec<serde_json::Value> =
        ["T-1", "T-2", "T-3", "T-4", "T-5"].iter().map(|t| json!({"ObjectIdentifier": t, "ObjectType": "CertTemplate"})).collect();
    write(d, "a_enterprisecas.json", "enterprisecas", json!([{"ObjectIdentifier": "E-1", "HostingComputer": format!("{D}-1105"),
        "Properties": {"name": "CORP-CA@CORP.LOCAL", "certthumbprint": "BB", "certchain": ["BB", "AA"], "domainsid": D},
        "EnabledCertTemplates": published, "Aces": []}]));
    let t = |id: &str, name: &str, schema: u32, ess: bool, ekus: serde_json::Value| {
        json!({"ObjectIdentifier": id, "Properties": {"name": name, "domainsid": D, "schemaversion": schema, "authorizedsignatures": 0,
              "requiresmanagerapproval": false, "authenticationenabled": false, "enrolleesuppliessubject": ess, "effectiveekus": ekus},
              "Aces": [{"PrincipalSID": du, "PrincipalType": "Group", "RightName": "Enroll", "IsInherited": false}]})
    };
    write(
        d,
        "a_certtemplates.json",
        "certtemplates",
        json!([
            t("T-1", "WEBSERVER@CORP.LOCAL", 1, true, json!(["1.3.6.1.5.5.7.3.1"])),
            t("T-2", "ANYPURPOSE@CORP.LOCAL", 2, false, json!(["2.5.29.37.0"])),
            t("T-3", "NOEKU@CORP.LOCAL", 2, false, json!([])),
            t("T-4", "SERVERONLY@CORP.LOCAL", 2, false, json!(["1.3.6.1.5.5.7.3.1"])),
            t("T-5", "V1NOSUBJECT@CORP.LOCAL", 1, false, json!(["1.3.6.1.5.5.7.3.1"])),
            // Not published: never reported.
            t("T-6", "UNPUBLISHED@CORP.LOCAL", 1, true, json!([]))
        ]),
    );
}

fn hits(g: &Graph, id: &str) -> Vec<String> {
    let def = CATALOG.iter().find(|d| d.id == id).unwrap_or_else(|| panic!("no finding {id}"));
    let r = ch_query::run_with(g, def.query, 1000, &ch_query::Cancel::new(None)).unwrap_or_else(|e| panic!("{id}: {}", e.message));
    let mut v: Vec<String> = r.edges.iter().map(|&(s, d, k)| format!("{} -{}-> {}", g.name(s), g.edge_kind_name(k), g.name(d))).collect();
    v.sort();
    v
}

#[test]
fn esc2_esc5_esc15_findings() {
    let d = dir("adcs-findings");
    fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    assert_eq!(hits(g, "adcs-esc15"), ["DOMAIN USERS@CORP.LOCAL -Enroll-> WEBSERVER@CORP.LOCAL"]);
    assert_eq!(
        hits(g, "adcs-any-purpose"),
        ["DOMAIN USERS@CORP.LOCAL -Enroll-> ANYPURPOSE@CORP.LOCAL", "DOMAIN USERS@CORP.LOCAL -Enroll-> NOEKU@CORP.LOCAL"]
    );
    assert_eq!(hits(g, "adcs-pki-object-control"), ["ALICE@CORP.LOCAL -GenericWrite-> NTAUTHCERTIFICATES@CORP.LOCAL"]);
    let _ = fs::remove_dir_all(&d);
}
