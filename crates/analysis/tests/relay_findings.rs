//! Findings over NTLM relay edges and relay-related properties.

use ch_analysis::findings::CATALOG;
use ch_ingest::{build_graph, IngestOptions};
use ch_store::Graph;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-4-4-4";

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

fn fixture(d: &Path) {
    write(d, "r_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL", "functionallevel": "2016"}, "Aces": []}]));
    let member = |rid: u32| json!({"ObjectIdentifier": format!("{D}-{rid}"), "ObjectType": "Computer"});
    write(
        d,
        "r_groups.json",
        "groups",
        json!([
            {"ObjectIdentifier": format!("{D}-516"), "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"}, "Members": [member(1000), member(1001)], "Aces": []},
            {"ObjectIdentifier": "CORP.LOCAL-S-1-5-11", "Properties": {"name": "AUTHENTICATED USERS@CORP.LOCAL"}, "Members": [], "Aces": []}
        ]),
    );
    let ntlm = json!({"Collected": true, "Result": {"RestrictSendingNtlmTraffic": 0}});
    let web = json!({"Collected": true, "Result": true});
    let c = |rid: u32, name: &str, props: Value, extra: Value| {
        let mut p = json!({"name": name, "enabled": true, "domainsid": D});
        for (k, v) in props.as_object().unwrap() {
            p[k] = v.clone();
        }
        let mut c = json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": p, "PrimaryGroupSID": format!("{D}-515"), "Aces": [],
                           "NTLMRegistryData": ntlm, "IsWebClientRunning": web});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    };
    write(
        d,
        "r_computers.json",
        "computers",
        json!([
            // DC01 requires LDAP signing and channel binding; DC02 does not.
            c(1000, "DC01.CORP.LOCAL", json!({"isdc": true, "ldapsigning": true, "ldapenabled": true, "ldapsepa": true, "ldapsenabled": true}), json!({})),
            c(1001, "DC02.CORP.LOCAL", json!({"isdc": true, "ldapsigning": false, "ldapenabled": true, "ldapsepa": true, "ldapsenabled": true}), json!({})),
            c(1101, "WS01.CORP.LOCAL", json!({}), json!({})),
            c(1102, "SRV01.CORP.LOCAL", json!({}), json!({"SmbInfo": {"Collected": true, "Result": {"SigningEnabled": false}},
                "LocalAdmins": {"Collected": true, "Results": [member(1101)]}}))
        ]),
    );
}

fn hits(g: &Graph, id: &str) -> Vec<String> {
    let def = CATALOG.iter().find(|d| d.id == id).unwrap_or_else(|| panic!("no finding {id}"));
    let r = ch_query::run_with(g, def.query, 1000, &ch_query::Cancel::new(None)).unwrap_or_else(|e| panic!("{id}: {}", e.message));
    let mut v: Vec<String> = r.edges.iter().map(|&(s, d, k)| format!("{} -{}-> {}", g.name(s), g.edge_kind_name(k), g.name(d))).collect();
    if r.edges.is_empty() {
        v.extend(r.nodes.iter().map(|&n| g.name(n).to_string()));
    }
    v.sort();
    v
}

#[test]
fn relay_findings() {
    let d = dir("relay-findings");
    fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    let au = "AUTHENTICATED USERS@CORP.LOCAL";
    // DC01 relays to DC02's unsigned LDAP: a Tier Zero victim.
    assert_eq!(hits(g, "ntlm-relay-tier0"), [format!("{au} -CoerceAndRelayNTLMToLDAP-> DC01.CORP.LOCAL")]);
    // Every member computer runs WebClient in this fixture.
    assert_eq!(
        hits(g, "ntlm-relay-ldap"),
        [format!("{au} -CoerceAndRelayNTLMToLDAP-> SRV01.CORP.LOCAL"), format!("{au} -CoerceAndRelayNTLMToLDAP-> WS01.CORP.LOCAL")]
    );
    assert_eq!(hits(g, "ntlm-relay-smb"), [format!("{au} -CoerceAndRelayNTLMToSMB-> WS01.CORP.LOCAL")]);
    assert_eq!(hits(g, "dc-ldap-relay"), ["DC02.CORP.LOCAL"]);
    assert_eq!(hits(g, "smb-signing-off"), ["SRV01.CORP.LOCAL"]);
    assert!(hits(g, "ntlm-relay-adcs").is_empty());
    let _ = fs::remove_dir_all(&d);
}
