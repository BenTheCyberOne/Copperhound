use ch_engine::{shortest_path, tier0_analysis, EdgeFilter};
use ch_ingest::{build_graph, ingest, IngestOptions};
use ch_model::{ek, flags, NodeKind};
use ch_store::Graph;
use std::fs;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-e2e-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn sharphound_synthetic_end_to_end() {
    let dir = tmp("sh");
    let data = dir.join("data");
    let cfg = ch_synth::SynthConfig {
        users: 2_000,
        computers: 400,
        groups: 200,
        seed: 7,
    };
    let s = ch_synth::generate(&cfg, &data).unwrap();

    let opts = IngestOptions {
        batch_bytes: 64 << 10,
        ..Default::default()
    }; // force many batches
    let (_, r) = ingest(std::slice::from_ref(&data), &opts).unwrap();
    assert_eq!(r.dcsync_edges, 0, "DCSync is derived in post-processing");
    let b = build_graph(std::slice::from_ref(&data), &opts).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    let r = b.ingest;
    assert_eq!(r.parse_errors, 0, "{:?}", r.first_error);
    assert_eq!(r.records, s.objects);
    assert!(r.dcsync_edges >= 2);
    let g = b.graph;

    let out = dir.join("graph");
    g.write(&out).unwrap();
    drop(g);
    let g = Graph::open(&out).unwrap();

    let svc = g.lookup("SVC_BACKUP@SYNTH.LOCAL").expect("service account");
    assert_eq!(g.kind(svc), NodeKind::User);
    let dom = g.lookup(ch_synth::DOMAIN_SID).unwrap();
    assert_eq!(g.kind(dom), NodeKind::Domain);
    assert!(g.has_flag(dom, flags::TIER0));
    // Kinds from v6 meta-after-data and file names resolved.
    assert_eq!(
        g.kind(g.lookup("WS10.SYNTH.LOCAL").unwrap()),
        NodeKind::Computer
    );
    // DC computers are Tier Zero via Domain Controllers membership.
    assert!(g.has_flag(g.lookup("DC0.SYNTH.LOCAL").unwrap(), flags::TIER0));

    let f = EdgeFilter::traversable(&g);
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let p = shortest_path(&g, &[svc], &tier0, &f).unwrap();
    assert_eq!(p.kinds, vec![ek::DCSYNC]);

    let rep = tier0_analysis(&g, &f, 10);
    assert!(rep.exposed_principals > 0);
    assert!(!rep.choke_points.is_empty());
    drop(g);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ldapdomaindump_end_to_end() {
    let dir = tmp("ldd");
    let d = "S-1-5-21-11-22-33";
    fs::write(
        dir.join("domain_users.json"),
        format!(
            r#"[{{"attributes":{{"objectClass":["top","person","organizationalPerson","user"],"sAMAccountName":["alice"],"distinguishedName":["CN=Alice,OU=Staff,DC=corp,DC=local"],"objectSid":["{d}-1104"],"primaryGroupID":[513],"userAccountControl":[66048],"memberOf":["CN=Helpdesk,OU=Groups,DC=corp,DC=local"]}},"dn":"CN=Alice,OU=Staff,DC=corp,DC=local"}},
               {{"attributes":{{"objectClass":["user"],"sAMAccountName":["bob"],"distinguishedName":["CN=Bob,CN=Users,DC=corp,DC=local"],"objectSid":["{d}-1105"],"primaryGroupID":[513],"userAccountControl":[514],"adminCount":[1],"memberOf":["CN=Domain Admins,CN=Users,DC=corp,DC=local"]}}}}]"#
        ),
    )
    .unwrap();
    fs::write(
        dir.join("domain_groups.json"),
        format!(
            r#"[{{"attributes":{{"objectClass":["group"],"sAMAccountName":["Helpdesk"],"distinguishedName":["CN=Helpdesk,OU=Groups,DC=corp,DC=local"],"objectSid":["{d}-2001"],"memberOf":["CN=Domain Admins,CN=Users,DC=corp,DC=local"]}}}},
               {{"attributes":{{"objectClass":["group"],"sAMAccountName":["Domain Admins"],"distinguishedName":["CN=Domain Admins,CN=Users,DC=corp,DC=local"],"objectSid":["{d}-512"]}}}}]"#
        ),
    )
    .unwrap();

    let (parts, r) = ingest(std::slice::from_ref(&dir), &IngestOptions::default()).unwrap();
    assert_eq!(r.parse_errors, 0, "{:?}", r.first_error);
    assert_eq!(r.records, 4);
    let (g, _) = Graph::build(parts).unwrap();

    let alice = g.lookup("ALICE@CORP.LOCAL").unwrap();
    let bob = g.lookup("bob@corp.local").unwrap();
    let da = g.lookup("DOMAIN ADMINS@CORP.LOCAL").unwrap();
    assert!(g.has_flag(alice, flags::ENABLED));
    assert!(!g.has_flag(bob, flags::ENABLED));
    assert!(g.has_flag(bob, flags::ADMINCOUNT));
    assert!(g.has_flag(da, flags::TIER0));

    let p = shortest_path(&g, &[alice], &[da], &EdgeFilter::traversable(&g)).unwrap();
    assert_eq!(p.kinds, vec![ek::MEMBER_OF, ek::MEMBER_OF]); // alice → Helpdesk → DA
    let _ = fs::remove_dir_all(&dir);
}
