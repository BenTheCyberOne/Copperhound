use ch_engine::{shortest_path, EdgeFilter};
use ch_ingest::{build_graph, IngestOptions};
use ch_model::{flags, NodeKind};
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

fn write(d: &std::path::Path, file: &str, ty: &str, data: serde_json::Value) {
    let body = json!({"data": data, "meta": {"type": ty, "count": 1, "version": 6}});
    fs::write(d.join(file), body.to_string()).unwrap();
}

fn edge_names(g: &Graph, from: u32, to: u32) -> Vec<String> {
    let (ds, ks) = g.out_edges(from);
    ds.iter().zip(ks).filter(|(d, _)| **d == to).map(|(_, k)| g.edge_kind_name(*k).to_string()).collect()
}

fn ad_fixture(d: &std::path::Path) {
    let user = |rid: u32, name: &str| json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": {"name": name, "enabled": true, "domainsid": D}, "PrimaryGroupSID": format!("{D}-513"), "Aces": []});
    write(d, "t_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL"}, "Aces": []}]));
    write(d, "t_users.json", "users", json!([user(1104, "ALICE@CORP.LOCAL")]));
    write(
        d,
        "t_groups.json",
        "groups",
        json!([
            {"ObjectIdentifier": format!("{D}-513"), "Properties": {"name": "DOMAIN USERS@CORP.LOCAL"}, "Members": [], "Aces": []},
            {"ObjectIdentifier": format!("{D}-516"), "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"}, "Members": [{"ObjectIdentifier": format!("{D}-1000"), "ObjectType": "Computer"}], "Aces": []},
            {"ObjectIdentifier": "CORP.LOCAL-S-1-5-11", "Properties": {"name": "AUTHENTICATED USERS@CORP.LOCAL"}, "Members": [], "Aces": []}
        ]),
    );
    write(
        d,
        "t_computers.json",
        "computers",
        json!([
            {"ObjectIdentifier": format!("{D}-1000"), "Properties": {"name": "DC01.CORP.LOCAL", "enabled": true}, "PrimaryGroupSID": format!("{D}-516"),
             "DCRegistryData": {"CertificateMappingMethods": {"Collected": true, "Value": 4}, "StrongCertificateBindingEnforcement": {"Collected": true, "Value": 1}}},
            {"ObjectIdentifier": format!("{D}-1105"), "Properties": {"name": "CA01.CORP.LOCAL", "enabled": true}, "PrimaryGroupSID": format!("{D}-515")}
        ]),
    );
    write(d, "t_rootcas.json", "rootcas", json!([{"ObjectIdentifier": "R-0001", "DomainSID": D,
        "Properties": {"name": "CORP-ROOT@CORP.LOCAL", "certthumbprint": "AA", "certchain": ["AA"], "domainsid": D}, "Aces": []}]));
    write(d, "t_ntauthstores.json", "ntauthstores", json!([{"ObjectIdentifier": "N-0001", "DomainSID": D,
        "Properties": {"name": "NTAUTHCERTIFICATES@CORP.LOCAL", "certthumbprints": ["BB"], "domainsid": D}, "Aces": []}]));
    write(
        d,
        "t_enterprisecas.json",
        "enterprisecas",
        json!([{"ObjectIdentifier": "E-0001", "HostingComputer": format!("{D}-1105"),
          "Properties": {"name": "CORP-CA@CORP.LOCAL", "certthumbprint": "BB", "certchain": ["BB", "AA"], "domainsid": D,
                         "isuserspecifiessanenabledcollected": true},
          "EnabledCertTemplates": [{"ObjectIdentifier": "T-0001", "ObjectType": "CertTemplate"}, {"ObjectIdentifier": "T-0002", "ObjectType": "CertTemplate"}],
          "CARegistryData": {
             "CASecurity": {"Collected": true, "FailureReason": null, "Data": [
                {"PrincipalSID": "CORP.LOCAL-S-1-5-11", "PrincipalType": "Group", "RightName": "Enroll", "IsInherited": false}]},
             "IsUserSpecifiesSanEnabled": {"Collected": true, "FailureReason": null, "Value": true},
             "EnrollmentAgentRestrictions": {"Collected": true, "FailureReason": null, "Restrictions": []}},
          "Aces": []}]),
    );
    let tmpl = |id: &str, name: &str, ess: bool, nse: bool| {
        json!({"ObjectIdentifier": id, "Properties": {"name": name, "domainsid": D, "schemaversion": 2, "authorizedsignatures": 0,
              "requiresmanagerapproval": false, "authenticationenabled": true, "enrolleesuppliessubject": ess, "nosecurityextension": nse,
              "subjectaltrequiredns": false, "subjectaltrequiredomaindns": false, "subjectaltrequireupn": true,
              "effectiveekus": ["1.3.6.1.5.5.7.3.2"]},
              "Aces": [{"PrincipalSID": format!("{D}-513"), "PrincipalType": "Group", "RightName": "Enroll", "IsInherited": false}]})
    };
    write(d, "t_certtemplates.json", "certtemplates", json!([tmpl("T-0001", "ESC1@CORP.LOCAL", true, false), tmpl("T-0002", "USERSAN@CORP.LOCAL", false, true)]));
}

#[test]
fn adcs_esc_edges() {
    let d = dir("adcs");
    ad_fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let (dom, du, ca_host, eca, root, store, t1) = (id(D), id(&format!("{D}-513")), id("CA01.CORP.LOCAL"), id("E-0001"), id("R-0001"), id("N-0001"), id("T-0001"));

    assert_eq!(g.kind(eca), NodeKind::EnterpriseCa);
    assert!(g.has_flag(eca, flags::TIER0) && g.has_flag(ca_host, flags::TIER0));
    // Structural edges.
    assert!(edge_names(g, t1, eca).contains(&"PublishedTo".to_string()));
    assert!(edge_names(g, eca, root).contains(&"IssuedSignedBy".to_string()));
    assert!(edge_names(g, eca, store).contains(&"TrustedForNTAuth".to_string()));
    assert!(edge_names(g, root, dom).contains(&"RootCAFor".to_string()));
    // Composite edges: Authenticated Users holds CA Enroll → shortcut, so the
    // edge comes from the template enrollers (Domain Users).
    let du_edges = edge_names(g, du, dom);
    assert!(du_edges.contains(&"ADCSESC1".to_string()), "{du_edges:?}");
    assert!(du_edges.contains(&"ADCSESC6a".to_string()), "{du_edges:?}");
    assert!(du_edges.contains(&"ADCSESC6b".to_string()), "{du_edges:?}");
    assert!(edge_names(g, ca_host, dom).contains(&"GoldenCert".to_string()));
    let derived = b.post.passes.iter().find(|p| p.0 == "adcs").unwrap().1;
    // IssuedSignedBy, TrustedForNTAuth, ESC1, ESC6a, ESC6b, GoldenCert. ESC9 has
    // a victim (alice) but nobody holds write rights over her → no attacker edge.
    assert_eq!(derived, 6, "derived {derived}");

    let alice = id("ALICE@CORP.LOCAL");
    let p = shortest_path(g, &[alice], &[dom], &EdgeFilter::traversable(g)).unwrap();
    let hops: Vec<&str> = p.kinds.iter().map(|&k| g.edge_kind_name(k)).collect();
    assert_eq!(hops.len(), 2, "{hops:?}");
    assert_eq!(hops[0], "MemberOf");
    assert!(hops[1].starts_with("ADCSESC"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn azurehound_and_hybrid() {
    let d = dir("azure");
    ad_fixture(&d);
    let t = "9f0c1111-2222-3333-4444-555566667777";
    let ga = "62e90394-69f5-4237-9190-012177145e10";
    let items = json!([
        {"kind": "AZTenant", "data": {"tenantId": t, "displayName": "CONTOSO"}},
        {"kind": "AZUser", "data": {"id": "u-1", "userPrincipalName": "alice@contoso.com", "accountEnabled": true, "tenantId": t, "tenantName": "CONTOSO",
                                    "onPremisesSecurityIdentifier": format!("{D}-1104"), "onPremisesSyncEnabled": true}},
        {"kind": "AZUser", "data": {"id": "u-2", "userPrincipalName": "bob@contoso.com", "accountEnabled": true, "tenantId": t, "tenantName": "CONTOSO"}},
        {"kind": "AZGroupMember", "data": {"groupId": "g-1", "members": [{"groupId": "g-1", "member": {"@odata.type": "#microsoft.graph.user", "id": "u-2"}}]}},
        {"kind": "AZGroup", "data": {"id": "g-1", "displayName": "Helpdesk", "isAssignableToRole": false, "tenantId": t, "tenantName": "CONTOSO"}},
        {"kind": "AZRole", "data": {"id": ga, "templateId": ga, "displayName": "Global Administrator", "tenantId": t, "tenantName": "CONTOSO"}},
        {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": ga, "tenantId": t, "roleAssignments": [{"principalId": "u-1", "roleDefinitionId": ga, "directoryScopeId": "/"}]}},
        {"kind": "AZServicePrincipal", "data": {"id": "sp-1", "appId": "app-1", "displayName": "Deployer", "appDisplayName": "Deployer", "tenantId": t, "tenantName": "CONTOSO"}},
        {"kind": "AZServicePrincipal", "data": {"id": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000", "displayName": "Microsoft Graph", "tenantId": t, "tenantName": "CONTOSO"}},
        {"kind": "AZAppRoleAssignment", "data": {"appRoleId": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", "principalId": "sp-1", "principalType": "ServicePrincipal",
                                                 "resourceId": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000", "tenantId": t}},
        {"kind": "AZSubscription", "data": {"id": "/subscriptions/s1", "subscriptionId": "s1", "displayName": "Prod", "tenantId": t}},
        {"kind": "AZResourceGroup", "data": {"id": "/subscriptions/s1/resourceGroups/rg1", "name": "rg1", "subscriptionId": "/subscriptions/s1", "tenantId": t}},
        {"kind": "AZVM", "data": {"id": "/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1", "name": "vm1",
                                  "resourceGroupId": "/subscriptions/s1/resourceGroups/rg1", "tenantId": t, "identity": {"principalId": "sp-1"}}},
        {"kind": "AZVMAdminLogin", "data": {"virtualMachineId": "/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
            "adminLogins": [{"adminLogin": {"properties": {"principalId": "u-2", "scope": "/subscriptions/s1/resourceGroups/rg1"}}}]}}
    ]);
    fs::write(d.join("20261105_azurehound.json"), json!({"data": items, "meta": {"type": "azure", "version": 5, "count": 14}}).to_string()).unwrap();

    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let tenant = id(t);
    let role = id(&format!("{ga}@{t}"));
    let (u1, u2, grp, sp, app, vm) = (id("u-1"), id("u-2"), id("g-1"), id("sp-1"), id("app-1"), id("/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"));

    assert_eq!(g.kind(u1), NodeKind::AzUser);
    assert_eq!(g.name(u1), "ALICE@CONTOSO.COM");
    assert_eq!(g.name(grp), "HELPDESK@CONTOSO");
    assert!(g.has_flag(tenant, flags::TIER0) && g.has_flag(role, flags::TIER0));
    assert!(edge_names(g, u1, role).contains(&"AZHasRole".to_string()));
    assert!(edge_names(g, u1, tenant).contains(&"AZGlobalAdmin".to_string()));
    assert!(edge_names(g, u1, grp).contains(&"AZAddMembers".to_string()));
    assert!(edge_names(g, role, u2).contains(&"AZResetPassword".to_string()));
    assert!(edge_names(g, app, sp).contains(&"AZRunsAs".to_string()));
    assert!(edge_names(g, sp, role).contains(&"AZMGGrantRole".to_string()));
    assert!(edge_names(g, vm, sp).contains(&"AZManagedIdentity".to_string()));
    assert!(edge_names(g, u2, vm).contains(&"AZVMAdminLogin".to_string()), "RG-scope admin login should reach the VM");

    // Entra principals count toward Tier Zero exposure.
    let rep = ch_engine::tier0_analysis(g, &EdgeFilter::traversable(g), 5);
    assert!(rep.exposure.iter().any(|e| e.kind == "AZUser" && e.with_path >= 1), "{:?}", rep.exposure);

    // Hybrid: AD alice → Entra alice → Global Admin.
    let ad_alice = id("ALICE@CORP.LOCAL");
    assert!(edge_names(g, ad_alice, u1).contains(&"SyncedToEntraUser".to_string()));
    let p = shortest_path(g, &[ad_alice], &[tenant], &EdgeFilter::traversable(g)).unwrap();
    let hops: Vec<&str> = p.kinds.iter().map(|&k| g.edge_kind_name(k)).collect();
    assert_eq!(hops, vec!["SyncedToEntraUser", "AZGlobalAdmin"]);
    let _ = fs::remove_dir_all(&d);
}

/// Scoped directory-role assignments (administrative unit, single object, app)
/// and PIM approvers (`AZRoleManagementPolicyAssignment`).
#[test]
fn azure_scoped_roles_and_approvers() {
    let d = dir("azure-scoped");
    let t = "1f0c1111-2222-3333-4444-555566667777";
    let (ga, pra, paa) =
        ("62e90394-69f5-4237-9190-012177145e10", "e8611ab8-c189-46e8-94e1-60213ab1f814", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13");
    let (helpdesk, user_admin, cloud_app_admin) =
        ("729827e3-9c14-49f7-bb1b-9608f156bbb8", "fe930be7-5e62-47db-91af-98c3a49a38b1", "158c047a-c907-4556-b7ef-446551a6b5f7");
    let user = |id: &str| json!({"kind": "AZUser", "data": {"id": id, "userPrincipalName": format!("{id}@contoso.com"), "accountEnabled": true, "tenantId": t}});
    let role = |id: &str, name: &str| json!({"kind": "AZRole", "data": {"id": id, "templateId": id, "displayName": name, "tenantId": t}});
    // AzureHound writes the expanded scope; tenant-wide assignments carry an empty one.
    let tenant_wide = |p: &str, rd: &str| json!({"principalId": p, "roleDefinitionId": rd, "directoryScopeId": "/", "directoryScope": {"id": ""}});
    // AzureHound rewrites AU scopes (no appId) to "/".
    let au_scoped = |p: &str, rd: &str| json!({"principalId": p, "roleDefinitionId": rd, "directoryScopeId": "/",
        "directoryScope": {"id": "au-1", "@odata.type": "#microsoft.graph.administrativeUnit", "displayName": "Sales"}});
    let assign = |rd: &str, ras: Vec<serde_json::Value>| json!({"kind": "AZRoleAssignment", "data": {"roleDefinitionId": rd, "tenantId": t, "roleAssignments": ras}});
    let policy = |rd: &str, approval: bool, users: &[&str], groups: &[&str]| json!({"kind": "AZRoleManagementPolicyAssignment", "data": {
        "id": format!("Directory_{t}_{rd}"), "roleDefinitionId": rd.to_ascii_uppercase(), "tenantId": t.to_ascii_uppercase(),
        "endUserAssignmentRequiresApproval": approval, "endUserAssignmentUserApprovers": users, "endUserAssignmentGroupApprovers": groups}});
    let mut items = vec![json!({"kind": "AZTenant", "data": {"tenantId": t, "displayName": "CONTOSO"}})];
    for u in ["u-1", "u-2", "u-3", "u-4", "u-5", "u-6", "u-7", "u-8"] {
        items.push(user(u));
    }
    items.extend([
        json!({"kind": "AZGroup", "data": {"id": "g-appr", "displayName": "Approvers", "isAssignableToRole": true, "tenantId": t}}),
        json!({"kind": "AZApp", "data": {"id": "app-obj", "appId": "app-1", "displayName": "Web", "tenantId": t}}),
        role(ga, "Global Administrator"),
        role(pra, "Privileged Role Administrator"),
        role(paa, "Privileged Authentication Administrator"),
        role(helpdesk, "Helpdesk Administrator"),
        role(user_admin, "User Administrator"),
        role(cloud_app_admin, "Cloud Application Administrator"),
        // u-1: Helpdesk Admin over AU Sales; u-5: tenant-wide Helpdesk Admin.
        assign(helpdesk, vec![au_scoped("u-1", helpdesk), tenant_wide("u-5", helpdesk)]),
        // u-7: Privileged Authentication Admin over AU Sales only.
        assign(paa, vec![au_scoped("u-7", paa)]),
        // u-3: User Admin scoped to the single user u-4 (raw Graph object scope).
        assign(user_admin, vec![json!({"principalId": "u-3", "roleDefinitionId": user_admin, "directoryScopeId": "/u-4",
            "directoryScope": {"id": "u-4", "@odata.type": "#microsoft.graph.user"}})]),
        // u-8: Cloud App Admin scoped to app-1 (AzureHound's "/<appId>" form).
        assign(cloud_app_admin, vec![json!({"principalId": "u-8", "roleDefinitionId": cloud_app_admin, "directoryScopeId": "/app-1",
            "directoryScope": {"id": "app-obj", "appId": "app-1"}})]),
        assign(ga, vec![tenant_wide("u-2", ga)]),
        // PIM policies: GA needs approval by u-6 or g-appr; PAA needs approval with
        // no approvers listed (PRA/GA approve); User Admin needs no approval.
        policy(ga, true, &["u-6"], &["g-appr"]),
        policy(paa, true, &[], &[]),
        policy(user_admin, false, &["u-6"], &[]),
    ]);
    fs::write(d.join("20261109_azurehound.json"), json!({"data": items, "meta": {"type": "azure", "version": 5}}).to_string()).unwrap();

    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let has = |a: u32, b: u32, k: &str| edge_names(g, a, b).iter().any(|x| x == k);
    let out_kind = |a: u32, k: &str| -> Vec<u32> {
        let (ds, ks) = g.out_edges(a);
        ds.iter().zip(ks).filter(|(_, kk)| g.edge_kind_name(**kk) == k).map(|(&d, _)| d).collect()
    };
    let tenant = id(t);
    let role_node = |rd: &str| id(&format!("{rd}@{t}"));
    let (u1, u2, u3, u4, u5, u6, u7, u8) = (id("u-1"), id("u-2"), id("u-3"), id("u-4"), id("u-5"), id("u-6"), id("u-7"), id("u-8"));

    // Tenant-wide assignments are unchanged.
    assert!(has(u5, role_node(helpdesk), "AZHasRole"));
    assert!(has(role_node(helpdesk), u4, "AZResetPassword"), "user without roles");
    assert!(has(u2, tenant, "AZGlobalAdmin"));
    assert!(g.has_flag(role_node(ga), flags::TIER0) && g.has_flag(role_node(paa), flags::TIER0));

    // AU-scoped Helpdesk Admin: a scoped role node, visible, granting nothing tenant-wide.
    assert!(!has(u1, role_node(helpdesk), "AZHasRole"));
    let s1 = id(&format!("{helpdesk}/au-1@{t}"));
    assert!(has(u1, s1, "AZHasRole"));
    assert_eq!(g.kind(s1), NodeKind::AzRole);
    assert_eq!(g.name(s1), "HELPDESK ADMINISTRATOR (SCOPE: SALES)");
    let au = id("au-1");
    assert!(has(s1, au, "AZScopedTo"));
    assert_eq!(g.name(au), "SALES");
    assert!(out_kind(s1, "AZResetPassword").is_empty());
    let p: serde_json::Value = serde_json::from_str(g.props(s1)).unwrap();
    assert_eq!((p["scopeType"].as_str(), p["scoped"].as_bool()), (Some("administrativeUnit"), Some(true)));

    // AU-scoped Privileged Authentication Admin is not Tier Zero and has no tenant edge.
    let s3 = id(&format!("{paa}/au-1@{t}"));
    assert!(has(u7, s3, "AZHasRole") && !g.has_flag(s3, flags::TIER0));
    assert!(!has(u7, tenant, "AZPrivilegedAuthAdmin"));
    let f = EdgeFilter::traversable(g);
    assert!(shortest_path(g, &[u7], &g.nodes_with_flag(flags::TIER0), &f).is_none(), "AU-scoped PAA must not reach Tier Zero");
    assert!(shortest_path(g, &[u2], &g.nodes_with_flag(flags::TIER0), &f).is_some());

    // Object-scoped User Admin resets only that user; scoped role holders still count as
    // role holders for the tenant-wide Helpdesk rule (u-3 holds User Admin).
    let s2 = id(&format!("{user_admin}/u-4@{t}"));
    assert!(has(u3, s2, "AZHasRole") && has(s2, u4, "AZScopedTo"));
    assert_eq!(out_kind(s2, "AZResetPassword"), vec![u4]);
    assert!(!has(role_node(helpdesk), u3, "AZResetPassword"));
    assert!(!has(role_node(helpdesk), u7, "AZResetPassword"), "u-7 holds Privileged Authentication Admin (AU-scoped)");
    assert!(has(role_node(helpdesk), u1, "AZResetPassword"), "u-1 holds only Helpdesk Admin, which Helpdesk Admins may reset");

    // App-scoped Cloud App Admin keeps the direct edge to the app.
    assert!(has(u8, id("app-1"), "AZCloudAppAdmin"));

    // PIM approvers.
    assert!(has(u6, role_node(ga), "AZRoleApprover"));
    assert!(has(id("g-appr"), role_node(ga), "AZRoleApprover"));
    assert!(has(role_node(pra), role_node(paa), "AZRoleApprover") && has(role_node(ga), role_node(paa), "AZRoleApprover"));
    assert!(!has(u6, role_node(user_admin), "AZRoleApprover"), "no approval required");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn adcs_composition() {
    use ch_ingest::postprocess::explain::compose;
    let d = dir("adcs-compose");
    ad_fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let (dom, du, ca_host) = (id(D), id(&format!("{D}-513")), id("CA01.CORP.LOCAL"));
    let show = |s: u32, kind: &str, t: u32| {
        let c = compose(g, s, t, g.edge_kind_id(kind).unwrap()).expect("composite edge");
        let edges: Vec<String> =
            c.edges.iter().map(|&(a, b, k)| format!("{} -{}-> {}", g.name(a), g.edge_kind_name(k), g.name(b))).collect();
        eprintln!("{kind}: complete={} edges={edges:#?} notes={:#?}", c.complete, c.notes);
        assert!(c.complete, "{:?}", c.notes);
        edges
    };
    let esc1 = show(du, "ADCSESC1", dom);
    for want in ["-PublishedTo->", "-RootCAFor->", "-TrustedForNTAuth->", "-NTAuthStoreFor->", "-HostsCAService->", "-Enroll->"] {
        assert!(esc1.iter().any(|e| e.contains(want)), "{want} missing from {esc1:?}");
    }
    show(du, "ADCSESC6b", dom);
    let golden = show(ca_host, "GoldenCert", dom);
    assert!(golden.iter().any(|e| e.contains("-HostsCAService->")));
    // Not composite / not present.
    assert!(compose(g, du, dom, g.edge_kind_id("MemberOf").unwrap()).is_none());
    let _ = fs::remove_dir_all(&d);
}
