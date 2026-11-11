//! End-to-end: combined SharpHound + AzureHound fixture → hybrid links,
//! Entra Connect / Seamless SSO Tier Zero, trust edges and CoerceToTGT.

use ch_engine::{shortest_path, tier0_analysis, EdgeFilter};
use ch_ingest::{build_graph, IngestOptions};
use ch_model::flags;
use ch_store::Graph;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-10-20-30";
const CHILD: &str = "S-1-5-21-10-20-31";
const OTHER: &str = "S-1-5-21-70-80-90";
const T: &str = "11111111-2222-3333-4444-555555555555";
const GA: &str = "62e90394-69f5-4237-9190-012177145e10";
const DIR_SYNC: &str = "d29b2b05-8046-44ba-8758-1e26182fcf32";
const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
/// objectGUID 9F3A3E6C-1B7D-4C4E-9A0B-3F1D2E4C5B6A as onPremisesImmutableId.
const BOB_GUID: &str = "9F3A3E6C-1B7D-4C4E-9A0B-3F1D2E4C5B6A";
const BOB_ANCHOR: &str = "bD46n30bTkyaCz8dLkxbag==";

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

fn has_edge(g: &Graph, from: u32, to: u32, kind: &str) -> bool {
    let (ds, ks) = g.out_edges(from);
    ds.iter().zip(ks).any(|(d, k)| *d == to && g.edge_kind_name(*k) == kind)
}

fn fixture(d: &Path) {
    let trust = |sid: &str, name: &str, ty: &str, dir: &str, sidf: bool, tgt: bool| {
        json!({"TargetDomainSid": sid, "TargetDomainName": name, "TrustType": ty, "TrustDirection": dir,
               "IsTransitive": true, "SidFilteringEnabled": sidf, "TGTDelegationEnabled": tgt})
    };
    write(d, "h_domains.json", "domains", json!([
        {"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL"}, "Aces": [
            {"PrincipalSID": format!("{D}-1110"), "PrincipalType": "User", "RightName": "GetChanges"},
            {"PrincipalSID": format!("{D}-1110"), "PrincipalType": "User", "RightName": "GetChangesAll"}],
         "Trusts": [trust(CHILD, "EU.CORP.LOCAL", "ParentChild", "Bidirectional", false, false),
                    // CORP trusts OTHER (outbound): OTHER can attack CORP.
                    trust(OTHER, "OTHER.LOCAL", "Forest", "Outbound", false, true)]},
        {"ObjectIdentifier": CHILD, "Properties": {"name": "EU.CORP.LOCAL"}, "Aces": [],
         "Trusts": [trust(D, "CORP.LOCAL", 0.to_string().as_str(), "Bidirectional", false, false)]}
    ]));
    let user = |rid: u32, name: &str, extra: serde_json::Value| {
        let mut p = json!({"name": name, "enabled": true, "domainsid": D});
        p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": p, "PrimaryGroupSID": format!("{D}-513"), "Aces": []})
    };
    write(d, "h_users.json", "users", json!([
        user(1104, "ALICE@CORP.LOCAL", json!({})),
        user(1105, "BOB@CORP.LOCAL", json!({"objectguid": BOB_GUID})),
        user(1106, "DAVE@CORP.LOCAL", json!({})),
        user(1107, "CAROL@CORP.LOCAL", json!({})),
        user(1110, "MSOL_0A1B2C3D4E5F@CORP.LOCAL", json!({"description":
            "Account created by Microsoft Azure Active Directory Connect with installation identifier 0a1b running on computer AADC01 configured to synchronize to tenant corp.onmicrosoft.com."}))
    ]));
    // OTHER keeps the trust account for CORP (CORP trusts OTHER).
    write(d, "h_other_users.json", "users", json!([
        {"ObjectIdentifier": format!("{OTHER}-1201"), "Properties": {"name": "CORP$@OTHER.LOCAL", "samaccountname": "CORP$", "enabled": true, "domainsid": OTHER},
         "Aces": []}
    ]));
    write(d, "h_groups.json", "groups", json!([
        {"ObjectIdentifier": format!("{D}-512"), "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"}, "Members": [], "Aces": []},
        {"ObjectIdentifier": format!("{D}-516"), "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"},
         "Members": [{"ObjectIdentifier": format!("{D}-1000"), "ObjectType": "Computer"}], "Aces": []},
        {"ObjectIdentifier": format!("{D}-2001"), "Properties": {"name": "HELPDESK@CORP.LOCAL"},
         "Members": [{"ObjectIdentifier": format!("{D}-1107"), "ObjectType": "User"}],
         "Aces": [{"PrincipalSID": format!("{D}-1104"), "PrincipalType": "User", "RightName": "AddSelf"}]}
    ]));
    let computer = |rid: u32, name: &str, ud: bool, extra: serde_json::Value| {
        let mut c = json!({"ObjectIdentifier": format!("{D}-{rid}"),
            "Properties": {"name": name, "enabled": true, "domainsid": D, "unconstraineddelegation": ud},
            "PrimaryGroupSID": format!("{D}-515"), "Aces": []});
        c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        c
    };
    write(d, "h_computers.json", "computers", json!([
        computer(1000, "DC01.CORP.LOCAL", true, json!({"PrimaryGroupSID": format!("{D}-516")})),
        computer(1200, "AADC01.CORP.LOCAL", false, json!({"LocalGroups": [{"ObjectIdentifier": format!("{D}-1200-544"),
            "Name": "ADMINISTRATORS@AADC01.CORP.LOCAL", "Collected": true,
            "Results": [{"ObjectIdentifier": format!("{D}-2001"), "ObjectType": "Group"}]}]})),
        computer(1201, "AZUREADSSOACC.CORP.LOCAL", false, json!({})),
        computer(1202, "LEGACY01.CORP.LOCAL", true, json!({}))
    ]));

    let az_user = |id: &str, upn: &str, extra: serde_json::Value| {
        let mut u = json!({"id": id, "userPrincipalName": upn, "accountEnabled": true, "tenantId": T, "tenantName": "CORP"});
        u.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!({"kind": "AZUser", "data": u})
    };
    let synced = |rid: u32| json!({"onPremisesSecurityIdentifier": format!("{D}-{rid}"), "onPremisesSyncEnabled": true});
    let role = |tpl: &str, name: &str| json!({"kind": "AZRole", "data": {"id": tpl, "templateId": tpl, "displayName": name, "tenantId": T, "tenantName": "CORP"}});
    let assign = |tpl: &str, p: &str| json!({"kind": "AZRoleAssignment", "data": {"roleDefinitionId": tpl, "tenantId": T,
        "roleAssignments": [{"principalId": p, "roleDefinitionId": tpl, "directoryScopeId": "/"}]}});
    let items = json!([
        {"kind": "AZTenant", "data": {"tenantId": T, "displayName": "CORP"}},
        az_user("az-alice", "alice@corp.com", synced(1104)),
        az_user("az-bob", "bob@corp.com", json!({"onPremisesImmutableId": BOB_ANCHOR, "onPremisesSyncEnabled": true})),
        az_user("az-dave", "dave@corp.com", synced(1106)),
        az_user("az-sync", "Sync_AADC01_0a1b2c3d4e5f@corp.onmicrosoft.com", json!({"displayName": "On-Premises Directory Synchronization Service Account"})),
        {"kind": "AZGroup", "data": {"id": "az-helpdesk", "displayName": "Helpdesk", "isAssignableToRole": true, "tenantId": T, "tenantName": "CORP",
                                     "onPremisesSecurityIdentifier": format!("{D}-2001"), "onPremisesSyncEnabled": true}},
        role(GA, "Global Administrator"), role(DIR_SYNC, "Directory Synchronization Accounts"), role(USER_ADMIN, "User Administrator"),
        assign(GA, "az-dave"), assign(DIR_SYNC, "az-sync"), assign(USER_ADMIN, "az-helpdesk")
    ]);
    fs::write(d.join("h_azurehound.json"), json!({"data": items, "meta": {"type": "azure", "version": 5}}).to_string()).unwrap();
}

#[test]
fn hybrid_and_trust_end_to_end() {
    let d = dir("hybrid");
    fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let (alice, bob, dave, carol, msol) = (
        id("ALICE@CORP.LOCAL"),
        id("BOB@CORP.LOCAL"),
        id("DAVE@CORP.LOCAL"),
        id("CAROL@CORP.LOCAL"),
        id("MSOL_0A1B2C3D4E5F@CORP.LOCAL"),
    );
    let (az_alice, az_bob, az_dave, az_sync) = (id("az-alice"), id("az-bob"), id("az-dave"), id("az-sync"));
    let (helpdesk, az_helpdesk) = (id(&format!("{D}-2001")), id("az-helpdesk"));
    let (aadc, sso, legacy) = (id("AADC01.CORP.LOCAL"), id("AZUREADSSOACC.CORP.LOCAL"), id("LEGACY01.CORP.LOCAL"));
    let (corp, child, other, tenant) = (id(D), id(CHILD), id(OTHER), id(T));
    let sync_role = id(&format!("{DIR_SYNC}@{T}"));

    // Synced identities: by SID and by immutable id (objectGUID anchor).
    assert!(has_edge(g, alice, az_alice, "SyncedToEntraUser") && has_edge(g, az_alice, alice, "SyncedToADUser"));
    assert!(has_edge(g, bob, az_bob, "SyncedToEntraUser"), "immutable-id match");
    assert!(has_edge(g, helpdesk, az_helpdesk, "SyncedToEntraGroup") && has_edge(g, az_helpdesk, helpdesk, "SyncedToADGroup"));

    // Entra Connect: server holds both sync credentials; all Tier Zero.
    assert!(has_edge(g, aadc, msol, "EntraConnectCredentials"));
    assert!(has_edge(g, aadc, az_sync, "EntraConnectCredentials"));
    for n in [msol, az_sync, aadc, sso, sync_role] {
        assert!(g.has_flag(n, flags::TIER0), "{} should be Tier Zero", g.name(n));
    }
    assert!(b.post.tier0_added >= 4);
    assert!(has_edge(g, sync_role, az_alice, "AZResetPassword"));
    assert!(!has_edge(g, sync_role, id("az-sync"), "AZResetPassword"), "cloud-only users are not targets");

    // Seamless SSO: AZUREADSSOACC → synced users of CORP.
    assert!(has_edge(g, sso, az_alice, "SeamlessSSO") && has_edge(g, sso, az_dave, "SeamlessSSO"));
    assert!(!has_edge(g, sso, az_bob, "SeamlessSSO"), "no on-prem SID: domain unknown");

    // Trusts: forest closure both ways, cross-forest abuse edges in attack direction.
    assert!(has_edge(g, corp, child, "SameForestTrust") && has_edge(g, child, corp, "SameForestTrust"));
    assert!(has_edge(g, corp, other, "CrossForestTrust"));
    assert!(has_edge(g, other, corp, "SpoofSIDHistory") && has_edge(g, other, corp, "AbuseTGTDelegation"));
    assert!(!has_edge(g, corp, other, "SpoofSIDHistory"));
    // HasTrustKeys: CORP trusts OTHER, so CORP holds the key of OTHER's CORP$ account.
    let trust_acct = id("CORP$@OTHER.LOCAL");
    assert!(has_edge(g, corp, trust_acct, "HasTrustKeys"));
    assert!(!has_edge(g, other, trust_acct, "HasTrustKeys"));

    // CoerceToTGT: own domain and the whole forest, not the other forest
    // (OTHER does not trust CORP).
    assert!(has_edge(g, legacy, corp, "CoerceToTGT") && has_edge(g, legacy, child, "CoerceToTGT"));
    assert!(!has_edge(g, legacy, other, "CoerceToTGT"));

    // Hybrid paths to Tier Zero.
    let f = EdgeFilter::traversable(g);
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let p = shortest_path(g, &[dave], &tier0, &f).expect("AD dave → synced GA");
    assert_eq!(p.kinds.len(), 2);
    assert_eq!(g.edge_kind_name(p.kinds[0]), "SyncedToEntraUser");
    let p = shortest_path(g, &[alice], &[tenant], &f).expect("alice → tenant");
    assert_eq!(g.edge_kind_name(p.kinds[0]), "AddSelf", "AddSelf → synced Helpdesk → AADC01 / cloud roles");
    // Carol: Helpdesk → local admin of the Entra Connect server (Tier Zero).
    let p = shortest_path(g, &[carol], &[aadc], &f).unwrap();
    assert_eq!(p.kinds.len(), 2);

    // Unified Tier Zero switch: off, AD dave no longer reaches Entra Tier Zero.
    let split = EdgeFilter::traversable(g).unified_tier0(false);
    assert!(shortest_path(g, &[dave], &tier0, &split).is_none());
    let on = tier0_analysis(g, &f, 5);
    let off = tier0_analysis(g, &split, 5);
    assert!(off.exposed_principals < on.exposed_principals, "{} vs {}", off.exposed_principals, on.exposed_principals);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn synth_covers_trust_and_hybrid_edges() {
    let d = dir("synth-hybrid");
    let s = ch_synth::generate(&ch_synth::SynthConfig { users: 2_000, computers: 400, groups: 200, seed: 3 }, &d).unwrap();
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    assert_eq!(b.ingest.records, s.objects);
    let g = &b.graph;
    let mut counts = vec![0u64; g.edge_kind_count()];
    for &k in g.all_edge_kinds() {
        counts[k as usize] += 1;
    }
    for kind in [
        "SameForestTrust", "CrossForestTrust", "SpoofSIDHistory", "AbuseTGTDelegation", "CoerceToTGT",
        "SyncedToEntraUser", "SyncedToADUser", "SyncedToEntraGroup", "SyncedToADGroup", "SeamlessSSO", "EntraConnectCredentials",
    ] {
        let k = g.edge_kind_id(kind).unwrap_or_else(|| panic!("{kind} not registered"));
        assert!(counts[k as usize] > 0, "synth produced no {kind}");
    }
    let connect = g.lookup(&format!("{}.{}", ch_synth::CONNECT_HOST, ch_synth::DOMAIN_NAME)).unwrap();
    assert!(g.has_flag(connect, flags::TIER0));
    let _ = fs::remove_dir_all(&d);
}
