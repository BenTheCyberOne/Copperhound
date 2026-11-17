//! NTLM relay edges, ESC16, and the AD edges added with them (DCFor,
//! DumpSMSAPassword, SQLAdmin, ClaimSpecialIdentity, ProtectAdminGroups).
//! Each rule has a matching computer and computers that miss exactly one
//! condition.

use ch_ingest::{build_graph, IngestOptions};
use ch_store::Graph;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-7-7-7";

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

fn has(g: &Graph, from: u32, to: u32, kind: &str) -> bool {
    let (ds, ks) = g.out_edges(from);
    ds.iter().zip(ks).any(|(&x, &k)| x == to && g.edge_kind_name(k) == kind)
}

fn count(g: &Graph, kind: &str) -> usize {
    let Some(k) = g.edge_kind_id(kind) else { return 0 };
    (0..g.node_count() as u32).map(|s| g.out_edges(s).1.iter().filter(|&&x| x == k).count()).sum()
}

const NTLM_OK: &str = r#"{"Collected": true, "FailureReason": null, "Result": {"RestrictSendingNtlmTraffic": 0}}"#;
const NTLM_DENY: &str = r#"{"Collected": true, "FailureReason": null, "Result": {"RestrictSendingNtlmTraffic": 2}}"#;

fn computer(rid: u32, name: &str, extra: Value) -> Value {
    let mut c = json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": {"name": name, "enabled": true, "domainsid": D},
                       "PrimaryGroupSID": format!("{D}-515"), "Aces": []});
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    c
}

/// Variations of the base fixture.
#[derive(Clone, Copy)]
struct Opts {
    ldap_signing: bool,
    ldaps_epa: bool,
    guest_enabled: bool,
}

const BASE: Opts = Opts { ldap_signing: false, ldaps_epa: false, guest_enabled: true };

fn fixture(d: &Path, functional_level: &str, ca: Value, o: Opts) {
    write(d, "t_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL", "functionallevel": functional_level}, "Aces": []}]));
    let member = |rid: u32, ty: &str| json!({"ObjectIdentifier": format!("{D}-{rid}"), "ObjectType": ty});
    write(
        d,
        "t_groups.json",
        "groups",
        json!([
            {"ObjectIdentifier": format!("{D}-515"), "Properties": {"name": "DOMAIN COMPUTERS@CORP.LOCAL"}, "Members": [], "Aces": []},
            {"ObjectIdentifier": format!("{D}-516"), "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"}, "Members": [member(1000, "Computer")], "Aces": []},
            {"ObjectIdentifier": format!("{D}-525"), "Properties": {"name": "PROTECTED USERS@CORP.LOCAL"}, "Members": [member(1103, "Computer")], "Aces": []},
            {"ObjectIdentifier": format!("{D}-1200"), "Properties": {"name": "SERVER ADMINS@CORP.LOCAL"},
             "Members": [member(1101, "Computer"), member(1102, "Computer"), member(1103, "Computer"), member(1104, "Computer")], "Aces": []},
            {"ObjectIdentifier": "CORP.LOCAL-S-1-5-11", "Properties": {"name": "AUTHENTICATED USERS@CORP.LOCAL"}, "Members": [], "Aces": []},
            {"ObjectIdentifier": "CORP.LOCAL-S-1-1-0", "Properties": {"name": "EVERYONE@CORP.LOCAL"}, "Members": [], "Aces": []},
            {"ObjectIdentifier": "CORP.LOCAL-S-1-5-15", "Properties": {"name": "THIS ORGANIZATION@CORP.LOCAL"}, "Members": [], "Aces": []}
        ]),
    );
    let ntlm_ok: Value = serde_json::from_str(NTLM_OK).unwrap();
    let ntlm_deny: Value = serde_json::from_str(NTLM_DENY).unwrap();
    let webdav = json!({"Collected": true, "FailureReason": null, "Result": true});
    write(
        d,
        "t_computers.json",
        "computers",
        json!([
            computer(1000, "DC01.CORP.LOCAL", json!({"PrimaryGroupSID": format!("{D}-516"), "IsDC": true, "NTLMRegistryData": ntlm_ok,
                "Properties": {"name": "DC01.CORP.LOCAL", "enabled": true, "domainsid": D,
                               "ldapsigning": o.ldap_signing, "ldapenabled": true, "ldapsepa": o.ldaps_epa, "ldapsenabled": true}})),
            // Matches every rule.
            computer(1101, "WS01.CORP.LOCAL", json!({"IsWebClientRunning": webdav, "NTLMRegistryData": ntlm_ok})),
            // Restricts outgoing NTLM.
            computer(1102, "WS02.CORP.LOCAL", json!({"IsWebClientRunning": webdav, "NTLMRegistryData": ntlm_deny})),
            // In Protected Users.
            computer(1103, "WS03.CORP.LOCAL", json!({"IsWebClientRunning": webdav, "NTLMRegistryData": ntlm_ok})),
            // NTLM settings not collected: no edge is guessed.
            computer(1104, "WS04.CORP.LOCAL", json!({"IsWebClientRunning": webdav})),
            // WebClient not running: SMB only.
            computer(1107, "WS07.CORP.LOCAL", json!({"IsWebClientRunning": {"Collected": true, "Result": false}, "NTLMRegistryData": ntlm_ok})),
            // SMB signing off; administered by SERVER ADMINS and WS07; hosts an sMSA.
            computer(1105, "SRV01.CORP.LOCAL", json!({"SmbInfo": {"Collected": true, "FailureReason": null, "Result": {"SigningEnabled": false}},
                "LocalAdmins": {"Collected": true, "FailureReason": null, "Results": [member(1200, "Group"), member(1107, "Computer")]},
                "DumpSMSAPassword": [member(1300, "User")]})),
            // SMB signing not collected: no edge is guessed for its admin WS08.
            computer(1108, "WS08.CORP.LOCAL", json!({"NTLMRegistryData": ntlm_ok})),
            computer(1109, "SRV03.CORP.LOCAL", json!({"LocalAdmins": {"Collected": true, "Results": [member(1108, "Computer")]}})),
            // SMB signing required.
            computer(1106, "SRV02.CORP.LOCAL", json!({"SmbInfo": {"Collected": true, "Result": {"SigningEnabled": true}},
                "LocalAdmins": {"Collected": true, "Results": [member(1200, "Group")]}}))
        ]),
    );
    let user = |rid: u32, name: &str, extra: Value| {
        let mut u = json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": {"name": name, "enabled": true, "domainsid": D}, "Aces": []});
        for (k, v) in extra.as_object().unwrap() {
            u[k] = v.clone();
        }
        u
    };
    write(
        d,
        "t_users.json",
        "users",
        json!([
            user(501, "GUEST@CORP.LOCAL", json!({"Properties": {"name": "GUEST@CORP.LOCAL", "enabled": o.guest_enabled, "domainsid": D}})),
            user(1300, "SMSA$@CORP.LOCAL", json!({})),
            user(1301, "SVC_SQL@CORP.LOCAL", json!({"SPNTargets": [{"ComputerSID": format!("{D}-1105"), "Port": 1433, "Service": "SQLAdmin"}]})),
            user(1400, "ADMIN1@CORP.LOCAL", json!({"Properties": {"name": "ADMIN1@CORP.LOCAL", "enabled": true, "domainsid": D, "adminsdholderprotected": true}})),
            user(1401, "PLAIN@CORP.LOCAL", json!({}))
        ]),
    );
    write(
        d,
        "t_containers.json",
        "containers",
        json!([{"ObjectIdentifier": "C0000000-0000-0000-0000-00000000AD01",
                "Properties": {"name": "ADMINSDHOLDER@CORP.LOCAL", "domainsid": D, "distinguishedname": "CN=AdminSDHolder,CN=System,DC=corp,DC=local"}, "Aces": []}]),
    );
    if ca.is_null() {
        return;
    }
    write(d, "t_rootcas.json", "rootcas", json!([{"ObjectIdentifier": "R-0001", "DomainSID": D,
        "Properties": {"name": "CORP-ROOT@CORP.LOCAL", "certthumbprint": "AA", "certchain": ["AA"], "domainsid": D}, "Aces": []}]));
    write(d, "t_ntauthstores.json", "ntauthstores", json!([{"ObjectIdentifier": "N-0001", "DomainSID": D,
        "Properties": {"name": "NTAUTHCERTIFICATES@CORP.LOCAL", "certthumbprints": ["BB"], "domainsid": D}, "Aces": []}]));
    write(d, "t_enterprisecas.json", "enterprisecas", json!([ca]));
    write(
        d,
        "t_certtemplates.json",
        "certtemplates",
        json!([{"ObjectIdentifier": "T-0001", "Properties": {"name": "MACHINE@CORP.LOCAL", "domainsid": D, "schemaversion": 1, "authorizedsignatures": 0,
              "requiresmanagerapproval": false, "authenticationenabled": true, "enrolleesuppliessubject": false, "nosecurityextension": false,
              "subjectaltrequiredns": true, "effectiveekus": ["1.3.6.1.5.5.7.3.2"]},
              "Aces": [{"PrincipalSID": format!("{D}-515"), "PrincipalType": "Group", "RightName": "Enroll", "IsInherited": false}]}]),
    );
}

fn ca(endpoints: Value, rpc_enforced: Option<bool>, disabled: Option<&[&str]>, san: bool) -> Value {
    let mut reg = json!({
        "CASecurity": {"Collected": true, "Data": [{"PrincipalSID": "CORP.LOCAL-S-1-5-11", "PrincipalType": "Group", "RightName": "Enroll", "IsInherited": false}]},
        "IsUserSpecifiesSanEnabled": {"Collected": true, "Value": san},
        "EnrollmentAgentRestrictions": {"Collected": true, "Restrictions": []}
    });
    if let Some(v) = rpc_enforced {
        reg["RPCEncryptionEnforced"] = json!({"Collected": true, "Value": v});
    }
    if let Some(list) = disabled {
        reg["DisabledExtensions"] = json!({"Collected": true, "Data": list});
    }
    json!({"ObjectIdentifier": "E-0001", "HostingComputer": format!("{D}-1105"),
           "Properties": {"name": "CORP-CA@CORP.LOCAL", "certthumbprint": "BB", "certchain": ["BB", "AA"], "domainsid": D,
                          "isuserspecifiessanenabledcollected": true},
           "EnabledCertTemplates": [{"ObjectIdentifier": "T-0001", "ObjectType": "CertTemplate"}],
           "HttpEnrollmentEndpoints": endpoints, "CARegistryData": reg, "Aces": []})
}

fn build(d: &Path) -> Graph {
    let b = build_graph(&[d.to_path_buf()], &IngestOptions::default()).unwrap();
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let bad = ch_ingest::postprocess::explain::check_all(&b.graph);
    assert!(bad.is_empty(), "incomplete compositions: {bad:#?}");
    b.graph
}

#[test]
fn smb_and_ldap_relay() {
    let d = dir("relay-ad");
    fixture(&d, "2016", Value::Null, BASE);
    let g = build(&d);
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let au = id("CORP.LOCAL-S-1-5-11");
    let ws = |n: u32| id(&format!("WS0{n}.CORP.LOCAL"));
    let (smb, ldap, ldaps) = ("CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS");

    // WS01: admin of SRV01 (no SMB signing) through SERVER ADMINS, WebClient on.
    for k in [smb, ldap, ldaps] {
        assert!(has(&g, au, ws(1), k), "WS01 {k}");
    }
    // WS07: direct admin of SRV01, WebClient off.
    assert!(has(&g, au, ws(7), smb));
    assert!(!has(&g, au, ws(7), ldap) && !has(&g, au, ws(7), ldaps));
    // WS02 restricts NTLM, WS03 is a protected user, WS04 has no NTLM data.
    for n in [2, 3, 4] {
        for k in [smb, ldap, ldaps] {
            assert!(!has(&g, au, ws(n), k), "WS0{n} {k}");
        }
    }
    assert!(!has(&g, au, ws(8), smb), "SRV03's SMB signing was not collected");
    // SRV02 requires signing and the DC is nobody's admin target: exactly these edges.
    assert_eq!(count(&g, smb), 2);
    assert_eq!(count(&g, ldap), 1);
    assert_eq!(count(&g, ldaps), 1);

    // Other AD edges.
    let (dom, dc, srv) = (id(D), id("DC01.CORP.LOCAL"), id("SRV01.CORP.LOCAL"));
    assert!(has(&g, dc, dom, "DCFor"));
    assert_eq!(count(&g, "DCFor"), 1);
    assert!(has(&g, srv, id("SMSA$@CORP.LOCAL"), "DumpSMSAPassword"));
    assert!(has(&g, id("SVC_SQL@CORP.LOCAL"), srv, "SQLAdmin"));
    assert!(has(&g, id("CORP.LOCAL-S-1-1-0"), id("GUEST@CORP.LOCAL"), "ClaimSpecialIdentity"));
    assert!(has(&g, au, id("CORP.LOCAL-S-1-5-15"), "ClaimSpecialIdentity"));
    let holder = id("C0000000-0000-0000-0000-00000000AD01");
    assert!(has(&g, holder, id("ADMIN1@CORP.LOCAL"), "ProtectAdminGroups"));
    assert_eq!(count(&g, "ProtectAdminGroups"), 1);
    assert!(!g.is_traversable(g.edge_kind_id("ProtectAdminGroups").unwrap()));

    // A relay edge is a step on a path: Authenticated Users → WS01 → (admin) SRV01.
    let p = ch_engine::shortest_path(&g, &[au], &[srv], &ch_engine::EdgeFilter::traversable(&g)).unwrap();
    assert_eq!(p.kinds.len(), 2, "{:?}", p.kinds.iter().map(|&k| g.edge_kind_name(k)).collect::<Vec<_>>());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn protected_users_count_on_old_functional_levels() {
    // Before 2012 R2, Protected Users does not stop NTLM: WS03 becomes a victim.
    let d = dir("relay-2012");
    fixture(&d, "2012", Value::Null, Opts { guest_enabled: false, ..BASE });
    let g = build(&d);
    let (au, ws3) = (g.lookup("CORP.LOCAL-S-1-5-11").unwrap(), g.lookup("WS03.CORP.LOCAL").unwrap());
    assert!(has(&g, au, ws3, "CoerceAndRelayNTLMToLDAP"));
    // A disabled Guest account is not claimable.
    let (everyone, guest) = (g.lookup("CORP.LOCAL-S-1-1-0").unwrap(), g.lookup("GUEST@CORP.LOCAL").unwrap());
    assert!(!has(&g, everyone, guest, "ClaimSpecialIdentity"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn ldap_signing_and_channel_binding_are_separate() {
    for (signing, epa) in [(true, false), (false, true), (true, true)] {
        let d = dir(&format!("relay-ldap-{signing}-{epa}"));
        fixture(&d, "2016", Value::Null, Opts { ldap_signing: signing, ldaps_epa: epa, ..BASE });
        let g = build(&d);
        let (au, ws1) = (g.lookup("CORP.LOCAL-S-1-5-11").unwrap(), g.lookup("WS01.CORP.LOCAL").unwrap());
        assert_eq!(has(&g, au, ws1, "CoerceAndRelayNTLMToLDAP"), !signing, "signing={signing}");
        assert_eq!(has(&g, au, ws1, "CoerceAndRelayNTLMToLDAPS"), !epa, "epa={epa}");
        let _ = fs::remove_dir_all(&d);
    }
}

#[test]
fn adcs_relay_and_esc16() {
    let http = json!([{"Collected": true, "FailureReason": null,
        "Result": {"Url": "http://ca01.corp.local/certsrv/", "ADCSWebEnrollmentHTTP": true, "ADCSWebEnrollmentHTTPS": false, "ADCSWebEnrollmentEPA": false}}]);
    let https_epa = json!([{"Collected": true,
        "Result": {"Url": "https://ca01.corp.local/certsrv/", "ADCSWebEnrollmentHTTP": false, "ADCSWebEnrollmentHTTPS": true, "ADCSWebEnrollmentEPA": true}}]);
    let sid_ext = ["1.3.6.1.4.1.311.25.2"];
    // (name, endpoints, RPC encryption, disabled extensions, SAN flag, [ADCS, ADCSRPC, ESC16])
    type Case<'a> = (&'a str, Value, Option<bool>, Option<&'a [&'a str]>, bool, [bool; 3]);
    let cases: [Case; 5] = [
        ("all", http.clone(), Some(false), Some(&sid_ext), true, [true, true, true]),
        ("epa", https_epa.clone(), Some(true), Some(&sid_ext), false, [false, false, false]),
        ("rpc-only", https_epa, Some(false), Some(&[]), true, [false, true, false]),
        ("web-only", http.clone(), None, None, true, [true, false, false]),
        ("esc16-no-san", http, Some(true), Some(&sid_ext), false, [true, false, false]),
    ];
    for (name, eps, rpc, disabled, san, [web, rpc_edge, esc16]) in cases {
        let d = dir(&format!("relay-adcs-{name}"));
        fixture(&d, "2016", ca(eps, rpc, disabled, san), BASE);
        let g = build(&d);
        let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
        let au = id("CORP.LOCAL-S-1-5-11");
        let ws1 = id("WS01.CORP.LOCAL");
        assert_eq!(has(&g, au, ws1, "CoerceAndRelayNTLMToADCS"), web, "{name}: ADCS");
        assert_eq!(has(&g, au, ws1, "CoerceAndRelayNTLMToADCSRPC"), rpc_edge, "{name}: ADCSRPC");
        // Domain Computers can enroll; only computers passing the NTLM checks are victims.
        for n in [2, 3, 4] {
            let w = id(&format!("WS0{n}.CORP.LOCAL"));
            assert!(!has(&g, au, w, "CoerceAndRelayNTLMToADCS") && !has(&g, au, w, "CoerceAndRelayNTLMToADCSRPC"), "{name}: WS0{n}");
        }
        assert_eq!(has(&g, id(&format!("{D}-515")), id(D), "ADCSESC16"), esc16, "{name}: ESC16");
        let _ = fs::remove_dir_all(&d);
    }
}
