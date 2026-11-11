//! Remediation hand-off: commands per edge and tickets in fake Jira,
//! ServiceNow and webhook receivers.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode, Uri};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use ch_server::state::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn json_req(method: &str, uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder().uri(uri).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
}

/// Method, path+query, headers, JSON body.
type Seen = Arc<Mutex<Vec<(String, String, HeaderMap, Value)>>>;

/// One fake server answering like Jira (`/jira/...`), ServiceNow (`/sn/...`)
/// and a webhook (`/hook`).
async fn fake() -> (String, Seen) {
    let seen: Seen = Default::default();
    let s2 = seen.clone();
    let app = axum::Router::new().fallback(move |method: axum::http::Method, uri: Uri, headers: HeaderMap, body: axum::body::Bytes| {
        let seen = s2.clone();
        async move {
            let p = uri.path_and_query().map(|p| p.to_string()).unwrap_or_default();
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            seen.lock().push((method.to_string(), p.clone(), headers.clone(), v));
            let authed = headers.get("authorization").is_some_and(|a| a.to_str().unwrap().starts_with("Basic ") || a == "Bearer pat-ok");
            let (code, body) = match p.as_str() {
                _ if p.starts_with("/jira") && !authed => (401, json!({"errorMessages": ["unauthorized"]})),
                "/jira/rest/api/2/myself" => (200, json!({"displayName": "Sec Bot"})),
                "/jira/rest/api/2/issue" => (201, json!({"id": "10001", "key": format!("SEC-{}", seen.lock().len())})),
                p if p.starts_with("/sn/api/now/table/incident") => (201, json!({"result": {"sys_id": "abc123", "number": "INC0010001"}})),
                "/hook" => (200, json!({"id": 77})),
                _ => (404, json!({})),
            };
            (StatusCode::from_u16(code).unwrap(), axum::Json(body))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn remediation_tickets() {
    let data = std::env::temp_dir().join(format!("ch-server-tickets-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("uploads")).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    ch_synth::generate(&ch_synth::SynthConfig { users: 120, computers: 30, groups: 20, seed: 3 }, &data.join("uploads")).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let t = t.as_str();
    let (_, v) = call(&app, json_req("POST", "/api/v1/ingest", Some(t), json!({}))).await;
    let job = v["job_id"].as_str().unwrap().to_string();
    for _ in 0..600 {
        let (_, v) = call(&app, get(&format!("/api/v1/jobs/{job}"), t)).await;
        if v["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (s, v) = call(&app, json_req("POST", "/api/v1/query", Some(t), json!({"query": "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN u.objectid, g.objectid LIMIT 1"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (u, g) = (v["rows"][0][0].as_str().unwrap().to_string(), v["rows"][0][1].as_str().unwrap().to_string());
    let (_, v) = call(&app, json_req("POST", "/api/v1/query", Some(t), json!({"query": "MATCH (x)-[:AdminTo]->(c:Computer) RETURN x.objectid, c.objectid LIMIT 1"}))).await;
    let (a, c) = (v["rows"][0][0].as_str().unwrap().to_string(), v["rows"][0][1].as_str().unwrap().to_string());
    let edges = json!([{"src": u, "kind": "MemberOf", "dst": g}, {"src": a, "kind": "AdminTo", "dst": c}, {"src": "S-1-5-21-9-9-9-9", "kind": "MemberOf", "dst": g}]);

    // Commands per edge (viewer-level analysis).
    let (s, v) = call(&app, json_req("POST", "/api/v1/remediation/commands", Some(t), json!({"edges": edges}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["missing"].as_array().unwrap().len(), 1);
    let cmd = v["items"][0]["command"].as_str().unwrap();
    assert!(cmd.contains(&format!("Remove-ADGroupMember -Identity '{g}' -Members '{u}'")), "{cmd}");
    assert!(v["items"][1]["command"].as_str().unwrap().contains("S-1-5-32-544"));
    assert!(v["items"][0]["guidance"].as_str().unwrap().len() > 20);

    let (base, seen) = fake().await;
    let (s, v) = call(
        &app,
        json_req(
            "PUT",
            "/api/v1/tickets/targets",
            Some(t),
            json!({"targets": [
                {"id": "jira", "name": "Jira", "type": "jira", "url": format!("{base}/jira/"), "username": "bot@acme.test", "token": "jtokqq", "project": "SEC", "labels": ["copperhound"], "fields": {"priority": {"name": "High"}}},
                {"id": "sn", "name": "ServiceNow", "type": "servicenow", "url": format!("{base}/sn"), "username": "svc", "token": "snpwqq", "fields": {"assignment_group": "AD Team"}},
                {"id": "hook", "name": "Hook", "type": "webhook", "url": format!("{base}/hook"), "token": "hsecqq"},
                {"id": "pat", "name": "Jira DC", "type": "jira", "url": format!("{base}/jira"), "token": "pat-bad", "project": "SEC"}
            ]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let txt = v.to_string();
    assert!(!txt.contains("jtokqq") && !txt.contains("snpwqq") && !txt.contains("hsecqq"), "secrets redacted: {txt}");

    let (_, v) = call(&app, json_req("POST", "/api/v1/tickets/targets/jira/test", Some(t), json!({}))).await;
    assert_eq!(v, json!({"ok": true, "detail": "signed in as Sec Bot"}));
    let (_, v) = call(&app, json_req("POST", "/api/v1/tickets/targets/pat/test", Some(t), json!({}))).await;
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().contains("HTTP 401"), "{v}");

    // Jira: one issue for all edges.
    let (s, v) = call(&app, json_req("POST", "/api/v1/tickets", Some(t), json!({"target": "jira", "edges": edges, "note": "From the Q3 plan"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["created"].as_array().unwrap().len(), 1);
    let key = v["created"][0]["key"].as_str().unwrap().to_string();
    assert_eq!(v["created"][0]["url"], json!(format!("{base}/jira/browse/{key}")));
    assert_eq!(v["missing"].as_array().unwrap().len(), 1);
    {
        let s = seen.lock();
        let (m, p, h, body) = s.iter().rev().find(|r| r.1 == "/jira/rest/api/2/issue").unwrap().clone();
        assert_eq!((m.as_str(), p.as_str()), ("POST", "/jira/rest/api/2/issue"));
        use base64::Engine;
        let want = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("bot@acme.test:jtokqq"));
        assert_eq!(h["authorization"], want.as_str());
        let f = &body["fields"];
        assert_eq!((f["project"]["key"].as_str(), f["issuetype"]["name"].as_str(), f["priority"]["name"].as_str()), (Some("SEC"), Some("Task"), Some("High")));
        assert_eq!(f["labels"], json!(["copperhound"]));
        assert_eq!(f["summary"], "Remove 2 attack path edges (CopperHound)");
        let d = f["description"].as_str().unwrap();
        assert!(d.contains("From the Q3 plan") && d.contains("{noformat}") && d.contains(&format!("-Members '{u}'")) && d.contains("-[AdminTo]->"), "{d}");
    }

    // ServiceNow: one record per edge.
    let (s, v) = call(&app, json_req("POST", "/api/v1/tickets", Some(t), json!({"target": "sn", "edges": edges, "split": true}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["created"].as_array().unwrap().len(), 2);
    assert_eq!(v["created"][0]["key"], "INC0010001");
    assert_eq!(v["created"][0]["url"], json!(format!("{base}/sn/nav_to.do?uri=%2Fincident.do%3Fsys_id%3Dabc123")));
    {
        let s = seen.lock();
        let recs: Vec<_> = s.iter().filter(|r| r.1 == "/sn/api/now/table/incident").collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].3["assignment_group"], "AD Team");
        assert!(recs[0].3["short_description"].as_str().unwrap().starts_with("Remove MemberOf from "));
    }

    // Webhook: signed structured payload.
    let (s, v) = call(&app, json_req("POST", "/api/v1/tickets", Some(t), json!({"target": "hook", "edges": edges, "title": "Fix these"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["created"][0]["key"], "77");
    {
        let s = seen.lock();
        let (_, _, h, body) = s.iter().rev().find(|r| r.1 == "/hook").unwrap().clone();
        assert_eq!(h["x-copperhound-event"], "remediation.ticket");
        use hmac::Mac;
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"hsecqq").unwrap();
        m.update(&serde_json::to_vec(&body).unwrap());
        let sig: String = m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h["x-copperhound-signature"], format!("sha256={sig}").as_str());
        assert_eq!(body["title"], "Fix these");
        assert_eq!(body["items"].as_array().unwrap().len(), 2);
        assert_eq!(body["items"][0]["kind"], "MemberOf");
    }

    // Failure surfaces as 502; log lists the tickets made.
    let (s, v) = call(&app, json_req("POST", "/api/v1/tickets", Some(t), json!({"target": "pat", "edges": edges}))).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{v}");
    let (_, v) = call(&app, get("/api/v1/tickets", t)).await;
    let log = v.as_array().unwrap();
    assert_eq!(log.len(), 4);
    assert_eq!(log[0]["target"], "hook");
    assert_eq!(log[3]["key"], json!(key));
    assert_eq!(log[3]["edges"].as_array().unwrap().len(), 2);

    // Roles: viewers may read targets and get commands, not create tickets or change targets.
    let (_, _) = call(&app, json_req("POST", "/api/v1/users", Some(t), json!({"username": "vic", "password": "viewer-password-1", "role": "viewer"}))).await;
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"vic","password":"viewer-password-1"}))).await;
    let vt = v["token"].as_str().unwrap().to_string();
    let (s, _) = call(&app, get("/api/v1/tickets/targets", &vt)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, json_req("POST", "/api/v1/remediation/commands", Some(&vt), json!({"edges": edges}))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, json_req("POST", "/api/v1/tickets", Some(&vt), json!({"target": "hook", "edges": edges}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, json_req("PUT", "/api/v1/tickets/targets", Some(&vt), json!({"targets": []}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let _ = std::fs::remove_dir_all(&data);
}
