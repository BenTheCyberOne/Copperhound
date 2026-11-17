//! Members of Tier Zero groups are Tier Zero, transitively, except through
//! broad built-in groups.

use ch_ingest::{build_graph, IngestOptions};
use ch_model::flags;
use serde_json::json;
use std::fs;

const D: &str = "S-1-5-21-8-8-8";

#[test]
fn tier0_group_members_are_tier0() {
    let d = std::env::temp_dir().join(format!("ch-t0m-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let wrap = |ty: &str, data: serde_json::Value| json!({"data": data, "meta": {"type": ty, "count": 1, "version": 6}}).to_string();
    let m = |id: String, ty: &str| json!({"ObjectIdentifier": id, "ObjectType": ty});
    let user = |rid: u32, name: &str| json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": {"name": name, "enabled": true}, "Aces": []});
    fs::write(d.join("users.json"), wrap("users", json!([user(1101, "ADMIN1@X.LOCAL"), user(1102, "NESTED@X.LOCAL"), user(1103, "PLAIN@X.LOCAL")]))).unwrap();
    fs::write(
        d.join("groups.json"),
        wrap(
            "groups",
            json!([
                // DA ← ADMIN1, ← OPS ← NESTED; Domain Users is nested into Account Operators (a misconfiguration).
                {"ObjectIdentifier": format!("{D}-512"), "Properties": {"name": "DOMAIN ADMINS@X.LOCAL"},
                 "Members": [m(format!("{D}-1101"), "User"), m(format!("{D}-1300"), "Group")], "Aces": []},
                {"ObjectIdentifier": format!("{D}-1300"), "Properties": {"name": "OPS@X.LOCAL"}, "Members": [m(format!("{D}-1102"), "User")], "Aces": []},
                {"ObjectIdentifier": "X.LOCAL-S-1-5-32-548", "Properties": {"name": "ACCOUNT OPERATORS@X.LOCAL"}, "Members": [m(format!("{D}-513"), "Group")], "Aces": []},
                {"ObjectIdentifier": format!("{D}-513"), "Properties": {"name": "DOMAIN USERS@X.LOCAL"}, "Members": [m(format!("{D}-1103"), "User")], "Aces": []}
            ]),
        ),
    )
    .unwrap();
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let g = &b.graph;
    let t0 = |q: &str| g.has_flag(g.lookup(q).unwrap_or_else(|| panic!("{q}")), flags::TIER0);
    assert!(t0("ADMIN1@X.LOCAL"));
    assert!(t0("OPS@X.LOCAL") && t0("NESTED@X.LOCAL"), "nested membership");
    assert!(!t0("DOMAIN USERS@X.LOCAL") && !t0("PLAIN@X.LOCAL"), "not through broad groups");
    let _ = fs::remove_dir_all(&d);
}
