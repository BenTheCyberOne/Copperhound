//! OpenGraph ingest: custom node and edge kinds next to SharpHound data.

use ch_engine::{shortest_path, EdgeFilter};
use ch_ingest::{build_graph, IngestOptions};
use ch_model::{flags, NodeKind, CUSTOM_KIND_BASE};
use ch_store::Graph;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

const D: &str = "S-1-5-21-1-2-3";

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn has_edge(g: &Graph, s: u32, d: u32, kind: &str) -> bool {
    let Some(k) = g.edge_kind_id(kind) else { return false };
    let (ds, ks) = g.out_edges(s);
    ds.iter().zip(ks).any(|(&x, &kk)| x == d && kk == k)
}

fn fixture(d: &std::path::Path) {
    let sh = |file: &str, ty: &str, data: serde_json::Value| {
        let body = json!({"data": data, "meta": {"type": ty, "count": 1, "version": 6}});
        fs::write(d.join(file), body.to_string()).unwrap();
    };
    sh("x_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL"}, "Aces": []}]));
    sh(
        "x_users.json",
        "users",
        json!([{"ObjectIdentifier": format!("{D}-1104"), "Properties": {"name": "ALICE@CORP.LOCAL", "enabled": true, "domainsid": D},
                "PrimaryGroupSID": format!("{D}-513"), "Aces": []}]),
    );
    sh(
        "x_groups.json",
        "groups",
        json!([{"ObjectIdentifier": format!("{D}-512"), "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"}, "Members": [], "Aces": []}]),
    );
    let og = json!({
        "metadata": {"source_kind": "GitHub"},
        "graph": {
            "nodes": [
                {"id": "gh-user-1", "kinds": ["GHUser"], "properties": {"name": "alice-gh", "enabled": true}},
                {"id": "gh-org-1", "kinds": ["GHOrganization", "Tag_Tier_Zero"], "properties": {"name": "acme"}},
                {"id": "gh-repo-1", "kinds": ["GHRepository"], "properties": {"name": "infra", "private": true}},
                {"id": "gh-repo-2", "kinds": ["GHRepository"], "properties": {"name": "dup"}},
                {"id": "gh-repo-3", "kinds": ["GHRepository"], "properties": {"name": "dup"}},
                // A built-in kind: merges with the SharpHound record of the same id.
                {"id": format!("{D}-1104"), "kinds": ["User"], "properties": {"name": "ALICE@CORP.LOCAL", "githubid": "alice-gh"}},
                {"kinds": ["GHUser"], "properties": {"name": "no id"}}
            ],
            "edges": [
                {"kind": "GHOwns", "start": {"value": "gh-user-1"}, "end": {"value": "gh-org-1"}},
                {"kind": "GHCanPush", "start": {"value": "ALICE-GH", "match_by": "name"}, "end": {"value": "infra", "match_by": "name", "kind": "GHRepository"}},
                // AD user → GitHub account (custom edge into a custom node).
                {"kind": "GHLinkedAccount", "start": {"value": format!("{D}-1104")}, "end": {"value": "gh-user-1", "kind": "GHUser"}},
                // GitHub repo deploys to the domain: built-in edge kind between custom and AD nodes.
                {"kind": "GenericAll", "start": {"value": "gh-repo-1"}, "end": {"value": D}},
                // Ambiguous name: two repositories called "dup".
                {"kind": "GHCanPush", "start": {"value": "gh-user-1"}, "end": {"value": "dup", "match_by": "name"}},
                // Unknown name.
                {"kind": "GHCanPush", "start": {"value": "gh-user-1"}, "end": {"value": "nope", "match_by": "name"}}
            ]
        }
    });
    fs::write(d.join("github.json"), og.to_string()).unwrap();
}

#[test]
fn opengraph_custom_kinds_and_edges() {
    let d = dir("opengraph");
    fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    assert_eq!(b.ingest.parse_errors, 1, "the node without an id: {:?}", b.ingest.first_error);
    assert_eq!(b.ingest.name_edges_resolved, 1);
    assert_eq!(b.ingest.name_edges_unresolved, 2, "ambiguous + unknown name");
    assert_eq!(b.ingest.custom_node_kinds, 3);
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let (gu, org, repo, alice, dom) = (id("gh-user-1"), id("gh-org-1"), id("gh-repo-1"), id(&format!("{D}-1104")), id(D));

    // Custom kinds are numbered by name and stored in the graph meta.
    assert_eq!(g.custom_node_kinds(), &["GHOrganization", "GHRepository", "GHUser"]);
    assert_eq!(g.kind_name(gu), "GHUser");
    assert_eq!(g.kind_raw(org), CUSTOM_KIND_BASE);
    assert_eq!(g.kind(gu), NodeKind::Unknown, "built-in analysis sees custom kinds as Unknown");
    assert_eq!(g.kind(alice), NodeKind::User);
    assert_eq!(g.name(gu), "ALICE-GH");
    assert!(g.has_flag(gu, flags::ENABLED));
    assert!(g.has_flag(org, flags::TIER0), "Tag_Tier_Zero");
    assert!(g.props(repo).contains("\"kinds\":[\"GHRepository\",\"GitHub\"]"), "{}", g.props(repo));
    assert!(g.props(alice).contains("githubid"), "OpenGraph properties merge into the AD user: {}", g.props(alice));

    assert!(has_edge(g, gu, org, "GHOwns"));
    assert!(has_edge(g, gu, repo, "GHCanPush"), "name-matched edge");
    assert!(has_edge(g, alice, gu, "GHLinkedAccount"));
    assert!(has_edge(g, repo, dom, "GenericAll"));
    let k = g.edge_kind_id("GHOwns").unwrap();
    assert!(g.is_traversable(k), "custom edge kinds are traversable");

    // Attack path across systems: ALICE → GitHub account → repo → domain.
    let p = shortest_path(g, &[alice], &[dom], &EdgeFilter::traversable(g)).expect("path");
    let hops: Vec<&str> = p.kinds.iter().map(|&k| g.edge_kind_name(k)).collect();
    assert_eq!(hops, ["GHLinkedAccount", "GHCanPush", "GenericAll"]);

    // CHQL: custom labels and kind names.
    let cancel = ch_query::Cancel::new(None);
    let r = ch_query::run_with(g, "MATCH (n:GHRepository) RETURN n.name, labels(n)[0] ORDER BY n.name", 100, &cancel).unwrap();
    assert_eq!(r.rows.len(), 3, "{:?}", r.rows);
    assert_eq!(r.rows[0][1], json!("GHRepository"));
    let r = ch_query::run_with(g, "MATCH (u:User)-[:GHLinkedAccount]->(a:GHUser)-[:GHCanPush]->(x) RETURN x.name", 100, &cancel).unwrap();
    assert_eq!(r.rows, vec![vec![json!("INFRA")]]);
    let r = ch_query::run_with(g, "MATCH (n) WHERE n.kind = 'GHUser' RETURN count(n)", 100, &cancel).unwrap();
    assert_eq!(r.rows, vec![vec![json!(1)]]);
    assert!(ch_query::run_with(g, "MATCH (n:NoSuchKind) RETURN n", 10, &cancel).is_err());
    assert!(ch_query::parse_syntax("MATCH (n:NoSuchKind) RETURN n").is_ok());

    // Search by custom kind.
    assert_eq!(g.search_raw("alice", g.raw_kind_of("ghuser"), 10), vec![gu]);

    // Round trip through disk keeps custom kinds.
    let out = d.join("graph");
    g.write(&out).unwrap();
    let g2 = Graph::open(&out).unwrap();
    assert_eq!(g2.kind_name(g2.lookup("gh-user-1").unwrap()), "GHUser");
    assert_eq!(g2.custom_node_kinds(), g.custom_node_kinds());

    let bad = ch_ingest::postprocess::explain::check_all(g);
    assert!(bad.is_empty(), "{bad:#?}");
    let _ = fs::remove_dir_all(&d);
}
