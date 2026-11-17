//! Sessions from logon data (CopperHound logon export, Defender XDR JSON and
//! CSV) merged with SharpHound sessions, session metadata, and the max-age
//! filter.

use ch_ingest::{build_graph, IngestOptions};
use ch_store::{session_source as ss, Graph};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const D: &str = "S-1-5-21-3-3-3";
/// 2026-11-01T00:00:00Z, 2026-11-05T09:00:00Z, 2026-11-10T08:15:30Z, 2026-11-12T00:00:00Z.
const NOV1: i64 = 1_793_491_200;
const NOV5: i64 = 1_793_869_200;
const NOV10: i64 = 1_794_298_530;
const NOV12: i64 = 1_794_441_600;

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
    write(d, "20261101000000_domains.json", "domains", json!([{"ObjectIdentifier": D, "Properties": {"name": "CORP.LOCAL"}, "Aces": []}]));
    let user = |rid: u32, name: &str| json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": {"name": name, "enabled": true, "domainsid": D}, "Aces": []});
    write(d, "20261101000000_users.json", "users", json!([user(1101, "ALICE@CORP.LOCAL"), user(1102, "BOB@CORP.LOCAL"), user(1103, "CAROL@CORP.LOCAL")]));
    let comp = |rid: u32, name: &str, sessions: serde_json::Value| {
        json!({"ObjectIdentifier": format!("{D}-{rid}"), "Properties": {"name": name, "enabled": true, "domainsid": D}, "Aces": [], "Sessions": sessions})
    };
    write(
        d,
        "20261101000000_computers.json",
        "computers",
        json!([
            comp(1201, "WS01.CORP.LOCAL", json!({"Collected": true, "Results": [{"ComputerSID": format!("{D}-1201"), "UserSID": format!("{D}-1101")}]})),
            comp(1202, "WS02.CORP.LOCAL", json!({"Collected": true, "Results": []}))
        ]),
    );
    // CopperHound logon export.
    let logons = json!({"meta": {"type": "copperhound-logons", "version": 1}, "data": [
        {"computer": "ws02.corp.local", "user": format!("{D}-1102"), "logontype": 10, "first": "2026-11-09T07:00:00Z", "last": "2026-11-10T08:15:30Z"},
        // Older than the Defender row for the same session (read before this file).
        {"computer": "WS02.CORP.LOCAL", "user": format!("{D}-1101"), "logontype": 2, "last": "2026-11-09T07:00:00Z"},
        // Host name without the domain: matched to the unique WS01.* computer.
        {"computer": "ws01", "user": format!("{D}-1102"), "logontype": 11, "last": "2026-11-08T00:00:00Z"},
        // Network logon: no credentials left behind.
        {"computer": "WS02.CORP.LOCAL", "user": format!("{D}-1103"), "logontype": 3, "last": "2026-11-10T08:15:30Z"},
        // Refreshes the SharpHound session, matched by computer SID.
        {"computer": "ignored", "computersid": format!("{D}-1201"), "user": format!("{D}-1101"), "logontype": "Interactive", "last": "2026-11-12T00:00:00Z"},
        // Unknown computer, unknown user, local account: dropped.
        {"computer": "WS99.CORP.LOCAL", "user": format!("{D}-1101"), "logontype": 2, "last": "2026-11-10T00:00:00Z"},
        {"computer": "WS02.CORP.LOCAL", "user": format!("{D}-9999"), "logontype": 2, "last": "2026-11-10T00:00:00Z"},
        {"computer": "WS02.CORP.LOCAL", "user": "S-1-5-18", "logontype": 5, "last": "2026-11-10T00:00:00Z"},
        // A computer account as the "user": not a User node, dropped.
        {"computer": "WS02.CORP.LOCAL", "user": format!("{D}-1201"), "logontype": 2, "last": "2026-11-10T00:00:00Z"}
    ]});
    fs::write(d.join("logons.json"), logons.to_string()).unwrap();
    // Defender XDR DeviceLogonEvents, CSV (with a quoted, multi-line column) and JSON.
    let csv = format!(
        "Timestamp,DeviceName,ActionType,LogonType,AccountSid,AdditionalFields\r\n\
         2026-11-05T09:00:00Z,ws01.corp.local,LogonSuccess,RemoteInteractive,{D}-1103,\"{{\"\"IsLocalLogon\"\":false,\n\"\"x\"\":1}}\"\r\n\
         2026-11-06T09:00:00Z,ws01.corp.local,LogonFailed,RemoteInteractive,{D}-1102,\r\n"
    );
    fs::write(d.join("DeviceLogonEvents.csv"), csv).unwrap();
    let defender = json!([
        {"Timestamp": "2026-11-10T08:15:30.1234567Z", "DeviceName": "ws02.corp.local", "ActionType": "LogonSuccess", "LogonType": "Interactive", "AccountSid": format!("{D}-1101")}
    ]);
    fs::write(d.join("defender.json"), defender.to_string()).unwrap();
}

fn has(g: &Graph, c: u32, u: u32) -> bool {
    let (ds, ks) = g.out_edges(c);
    ds.iter().zip(ks).any(|(&x, &k)| x == u && k == ch_model::ek::HAS_SESSION)
}

#[test]
fn logon_sessions_merge_with_collector_sessions() {
    let d = dir("logons");
    fixture(&d);
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap();
    assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap_or_else(|| panic!("missing {q}"));
    let (ws1, ws2) = (id("WS01.CORP.LOCAL"), id("WS02.CORP.LOCAL"));
    let (alice, bob, carol) = (id("ALICE@CORP.LOCAL"), id("BOB@CORP.LOCAL"), id("CAROL@CORP.LOCAL"));

    assert!(has(g, ws2, bob), "logon export, RDP");
    assert!(!has(g, ws2, carol), "network logons do not count");
    assert!(has(g, ws1, carol), "Defender CSV");
    assert!(has(g, ws2, alice), "Defender JSON");
    assert!(has(g, ws1, bob), "short host name");
    assert_eq!(g.session(ws1, bob).unwrap().logon_types, 1 << 11, "the failed Defender logon adds nothing");
    assert_eq!(b.ingest.logon_sessions_matched, 6);
    let m = g.session(ws2, alice).unwrap();
    assert_eq!((m.first_seen, m.last_seen, m.sources), (NOV10 - 90_930, NOV10, ss::DEFENDER | ss::LOGON_EVENTS));
    assert_eq!(b.ingest.logon_sessions_unmatched, 3, "unknown host, unknown user, computer as user; S-1-5-18 is not a domain account");
    assert!(g.lookup(&format!("{D}-9999")).is_none(), "no node invented for an unknown user");

    // SharpHound session refreshed by the logon export.
    let m = g.session(ws1, alice).expect("metadata");
    assert_eq!((m.first_seen, m.last_seen), (NOV1, NOV12));
    assert_eq!(m.sources, ss::SESSIONS | ss::LOGON_EVENTS);
    assert_eq!(m.logon_types, 1 << 2);
    let m = g.session(ws2, bob).unwrap();
    assert_eq!((m.first_seen, m.last_seen, m.sources, m.logon_types), (NOV10 - 90_930, NOV10, ss::LOGON_EVENTS, 1 << 10));
    let m = g.session(ws1, carol).unwrap();
    assert_eq!((m.last_seen, m.sources), (NOV5, ss::DEFENDER));
    assert_eq!(g.sessions().len(), 5);
    assert!(g.session(ws2, carol).is_none());

    // Written and reopened, the metadata stays.
    let out = std::env::temp_dir().join(format!("ch-logons-graph-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out);
    g.write(&out).unwrap();
    let g2 = Graph::open(&out).unwrap();
    assert_eq!(g2.sessions(), g.sessions());
    let _ = fs::remove_dir_all(&out);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn max_age_drops_old_sessions() {
    let d = dir("logons-age");
    fixture(&d);
    // Newest time in the input is Nov 12; three days back is Nov 9.
    let opts = IngestOptions { session_max_age_secs: 3 * 86_400, ..Default::default() };
    let b = build_graph(std::slice::from_ref(&d), &opts).unwrap();
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap();
    let (ws1, ws2) = (id("WS01.CORP.LOCAL"), id("WS02.CORP.LOCAL"));
    let (alice, bob, carol) = (id("ALICE@CORP.LOCAL"), id("BOB@CORP.LOCAL"), id("CAROL@CORP.LOCAL"));
    assert!(!has(g, ws1, carol), "Nov 5 is older than Nov 9");
    assert!(g.session(ws1, carol).is_none());
    assert!(has(g, ws1, alice), "collected Nov 1, but seen again Nov 12");
    assert!(has(g, ws2, bob) && has(g, ws2, alice));
    assert!(!has(g, ws1, bob), "Nov 8 is older than Nov 9");
    assert_eq!(b.ingest.sessions_aged_out, 2);
    // Without logon data the SharpHound session (Nov 1) is the newest time: kept.
    let only = dir("logons-age-sh");
    for f in ["20261101000000_domains.json", "20261101000000_users.json", "20261101000000_computers.json"] {
        fs::copy(d.join(f), only.join(f)).unwrap();
    }
    let b = build_graph(std::slice::from_ref(&only), &opts).unwrap();
    assert_eq!(b.ingest.sessions_aged_out, 0);
    assert_eq!(b.graph.sessions().len(), 1);
    let _ = fs::remove_dir_all(&only);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn superseded_collector_sessions_leave_no_metadata() {
    let d = dir("logons-superseded");
    fixture(&d);
    for f in ["logons.json", "DeviceLogonEvents.csv", "defender.json"] {
        fs::remove_file(d.join(f)).unwrap();
    }
    // A newer collection of WS01 without the session; an undated file adds WS03.
    write(
        &d,
        "20261103000000_computers.json",
        "computers",
        json!([{"ObjectIdentifier": format!("{D}-1201"), "Properties": {"name": "WS01.CORP.LOCAL", "enabled": true, "domainsid": D}, "Aces": [],
                "Sessions": {"Collected": true, "Results": []}}]),
    );
    write(
        &d,
        "extra_computers.json",
        "computers",
        json!([{"ObjectIdentifier": format!("{D}-1203"), "Properties": {"name": "WS03.CORP.LOCAL", "enabled": true, "domainsid": D}, "Aces": [],
                "Sessions": {"Collected": true, "Results": [{"ComputerSID": format!("{D}-1203"), "UserSID": format!("{D}-1103")}]}}]),
    );
    let opts = IngestOptions { session_max_age_secs: 86_400, ..Default::default() };
    let b = build_graph(std::slice::from_ref(&d), &opts).unwrap();
    let g = &b.graph;
    let id = |q: &str| g.lookup(q).unwrap();
    assert!(!has(g, id("WS01.CORP.LOCAL"), id("ALICE@CORP.LOCAL")));
    assert!(g.session(id("WS01.CORP.LOCAL"), id("ALICE@CORP.LOCAL")).is_none());
    // Undated: kept whatever the age limit, with unknown times.
    let (ws3, carol) = (id("WS03.CORP.LOCAL"), id("CAROL@CORP.LOCAL"));
    assert!(has(g, ws3, carol));
    let m = g.session(ws3, carol).unwrap();
    assert_eq!((m.first_seen, m.last_seen, m.sources), (0, 0, ss::SESSIONS));
    assert_eq!(b.ingest.sessions_aged_out, 0);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn reingest_is_deterministic() {
    let d = dir("logons-det");
    fixture(&d);
    let a = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap().graph;
    let b = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap().graph;
    assert_eq!(a.sessions(), b.sessions());
    let _ = fs::remove_dir_all(&d);
}
