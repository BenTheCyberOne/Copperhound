use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use ch_server::state::AppState;
use serde_json::{json, Value};
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
    Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_api() {
    let data = std::env::temp_dir().join(format!("ch-server-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);

    // Health is public; everything else needs a token.
    let (s, v) = call(&app, Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["graph_loaded"], false);
    let (s, _) = call(&app, Request::builder().uri("/api/v1/stats").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"nope"}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();
    let t = token.as_str();

    // Query before any graph → 409.
    let (s, _) = call(&app, json_req("POST", "/api/v1/query", Some(t), json!({"query":"MATCH (n) RETURN n"}))).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Upload synthetic SharpHound files via multipart.
    let src = data.join("synth-src");
    ch_synth::generate(&ch_synth::SynthConfig { users: 300, computers: 60, groups: 40, seed: 3 }, &src).unwrap();
    let boundary = "XBOUNDARYX";
    let mut body = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\nContent-Type: application/json\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(&std::fs::read(&p).unwrap());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/upload")
        .header(header::AUTHORIZATION, format!("Bearer {t}"))
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(body))
        .unwrap();
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["uploaded"].as_array().unwrap().len(), 5);
    let (_, v) = call(&app, get("/api/v1/uploads", t)).await;
    assert_eq!(v.as_array().unwrap().len(), 5);

    // Ingest job and poll.
    let (s, v) = call(&app, json_req("POST", "/api/v1/ingest", Some(t), json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    let job = v["job_id"].as_str().unwrap().to_string();
    let mut state = String::new();
    for _ in 0..200 {
        let (_, v) = call(&app, get(&format!("/api/v1/jobs/{job}"), t)).await;
        state = v["state"].as_str().unwrap().to_string();
        if state == "done" || state == "failed" {
            assert_eq!(state, "done", "{v}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(state, "done");

    let (_, v) = call(&app, get("/api/v1/stats", t)).await;
    // users + computers + groups + 5 built-in groups + SYNTH/PARTNER domains,
    // + CHILD/FABRIKAM domains and AZUREADSSOACC,
    // + Entra tenant, 30 synced and 2 cloud-only users, 1 group, 3 roles.
    assert_eq!(v["nodes"].as_u64().unwrap(), 300 + 60 + 40 + 5 + 2 + (1 + 1 + 1) + (1 + 30 + 2 + 1 + 3));
    assert!(v["edge_kinds"]["MemberOf"].as_u64().unwrap() > 0);

    // Source manifest of the loaded graph, and per upload.
    let (s, v) = call(&app, get("/api/v1/sources", t)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["merge_policy"], "newest");
    let srcs = v["sources"].as_array().unwrap();
    assert_eq!(srcs.len(), 5);
    let users = srcs.iter().find(|s| s["file"] == "synth_users.json").unwrap();
    assert_eq!(users["format"], "sharphound");
    assert_eq!(users["objects"], 300);
    assert!(users["collected_at"].is_null(), "undated synth files");
    let (_, v) = call(&app, get("/api/v1/uploads", t)).await;
    let up = v.as_array().unwrap().iter().find(|u| u["name"] == "synth_users.json").unwrap().clone();
    assert_eq!(up["in_graph"], true);
    assert_eq!(up["sources"][0]["objects"], 300);

    let (_, v) = call(&app, get("/api/v1/search?q=svc_&limit=5", t)).await;
    let svc = &v.as_array().unwrap()[0];
    assert_eq!(svc["name"], "SVC_BACKUP@SYNTH.LOCAL");
    let svc_id = svc["id"].as_u64().unwrap();

    // Property filters over columns.
    let f = json!({"filter": {"and": [{"kind": "User"}, {"cmp": {"key": "domain", "op": "eq", "value": "synth.local"}}, {"cmp": {"key": "name", "op": "contains", "value": "vc_back"}}]}});
    let (s, v) = call(&app, json_req("POST", "/api/v1/nodes/filter", Some(t), f)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["total"], 1);
    assert_eq!(v["nodes"][0]["id"].as_u64(), Some(svc_id));
    let f = json!({"filter": {"kind": "User"}, "limit": 7, "offset": 295});
    let (_, v) = call(&app, json_req("POST", "/api/v1/nodes/filter", Some(t), f)).await;
    assert_eq!(v["total"], 300);
    assert_eq!(v["nodes"].as_array().unwrap().len(), 5);
    let (s, _) = call(&app, json_req("POST", "/api/v1/nodes/filter", Some(t), json!({"filter": {"kind": "Nope"}}))).await;
    assert!(s.is_client_error());
    let (_, v) = call(&app, get("/api/v1/columns", t)).await;
    assert_eq!(v["ready"], true, "{v}");
    assert!(v["columns"].as_array().unwrap().iter().any(|c| c["key"] == "domain" && c["type"] == "str"));
    // Substring matches once columns are ready.
    let (_, v) = call(&app, get("/api/v1/search?q=vc_back&limit=5", t)).await;
    assert_eq!(v[0]["id"].as_u64(), Some(svc_id), "{v}");

    let (_, v) = call(&app, get(&format!("/api/v1/nodes/{svc_id}"), t)).await;
    assert_eq!(v["kind"], "User");
    assert_eq!(v["properties"]["domain"], "SYNTH.LOCAL");
    assert!(v["edge_counts"]["out"]["DCSync"].as_u64().unwrap() == 1);

    let (s, v) = call(&app, json_req("POST", "/api/v1/path", Some(t), json!({"from": svc_id, "to_tier0": true}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["edges"][0]["kind"], "DCSync");

    // Edge composition: the replication rights behind the DCSync edge.
    let dom = v["edges"][0]["dst"].as_u64().unwrap();
    let (s, c) = call(&app, get(&format!("/api/v1/edges/composition?src={svc_id}&dst={dom}&kind=DCSync"), t)).await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["complete"], true, "{c}");
    let kinds: Vec<&str> = c["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"GetChanges") && kinds.contains(&"GetChangesAll"), "{kinds:?}");
    assert!(!c["notes"].as_array().unwrap().is_empty());
    let (s, _) = call(&app, get(&format!("/api/v1/edges/composition?src={svc_id}&dst={dom}&kind=MemberOf"), t)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&app, get(&format!("/api/v1/edges/composition?src={dom}&dst={svc_id}&kind=DCSync"), t)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, v) = call(
        &app,
        json_req("POST", "/api/v1/query", Some(t), json!({"query":"MATCH (g:Group)-[:AdminTo]->(c:Computer) RETURN g.name, count(c) LIMIT 3"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["columns"], json!(["g.name", "count(c)"]));
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);

    let (s, v) = call(&app, json_req("POST", "/api/v1/query", Some(t), json!({"query":"MATCH (n:Nope) RETURN n"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["position"].is_number());

    // ---- v1.1 additions
    let (_, h) = call(&app, Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap()).await;
    assert_eq!(h["generation"], 1);
    assert_eq!(h["limits"]["max_query_limit"], 100_000);
    let (_, v) = call(&app, get("/api/v1/edge-kinds", t)).await;
    let member_of = v.as_array().unwrap().iter().find(|k| k["name"] == "MemberOf").unwrap();
    assert_eq!(member_of["category"], "Active Directory");
    assert!(member_of["count"].as_u64().unwrap() > 0);
    assert!(v.as_array().unwrap().iter().any(|k| k["name"] == "ADCSESC1" && k["category"] == "ADCS" && k["composite"] == true));
    let (_, v) = call(&app, get("/api/v1/node-kinds", t)).await;
    assert!(v.as_array().unwrap().iter().any(|k| k["name"] == "User" && k["count"].as_u64().unwrap() == 300));
    assert!(v.as_array().unwrap().iter().any(|k| k["name"] == "AZTenant" && k["category"] == "Azure"));

    // All shortest paths agree with CHQL's allShortestPaths (separate implementation).
    let (s, all) = call(&app, json_req("POST", "/api/v1/path", Some(t), json!({"from": "USER7@SYNTH.LOCAL", "to_tier0": true, "all": true}))).await;
    assert_eq!(s, StatusCode::OK, "{all}");
    let (_, q) = call(
        &app,
        json_req("POST", "/api/v1/query", Some(t), json!({"query":"MATCH p = allShortestPaths((u {name:'USER7@SYNTH.LOCAL'})-[*1..]->(x {tier0:true})) RETURN p", "limit": 100000})),
    )
    .await;
    let edge_set = |v: &Value| {
        let mut e: Vec<String> = v["edges"].as_array().unwrap().iter().map(|e| format!("{}-{}-{}", e["src"], e["kind"], e["dst"])).collect();
        e.sort();
        e
    };
    assert!(!edge_set(&all).is_empty());
    assert_eq!(edge_set(&all), edge_set(&q), "all-shortest subgraphs differ");
    assert_eq!(all["all_paths"]["length"].as_u64().unwrap() as usize + 1, all["paths"][0].as_array().unwrap().len());

    let (_, v) = call(&app, json_req("POST", "/api/v1/path", Some(t), json!({"from": "USER7@SYNTH.LOCAL", "to_tier0": true}))).await;
    let hops = v["hops"].as_array().unwrap();
    assert_eq!(hops.len(), v["paths"][0].as_array().unwrap().len() - 1);
    assert_eq!(hops[0]["src"], v["paths"][0][0]);

    let (s, v) = call(
        &app,
        json_req("POST", "/api/v1/query", Some(t), json!({"query":"MATCH p = shortestPath((u:User {name:'USER7@SYNTH.LOCAL'})-[*1..]->(t {tier0:true})) RETURN p", "query_id": "abc", "timeout_ms": 10000})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["path_hops"][0].as_array().unwrap().len(), v["paths"][0].as_array().unwrap().len() - 1);
    let (_, v) = call(&app, Request::builder().method("DELETE").uri("/api/v1/query/abc").header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    assert_eq!(v["cancelled"], false, "finished queries are deregistered");

    let (_, v) = call(&app, get("/api/v1/nodes?ids=0,1,999999999", t)).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
    let (_, v) = call(&app, json_req("POST", "/api/v1/nodes/resolve", Some(t), json!({"objectids": [svc["objectid"], "NOPE"]}))).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (_, v) = call(&app, json_req("POST", "/api/v1/path", Some(t), json!({"from": svc_id, "to_tier0": true}))).await;
    assert_eq!(v["generation"], 1);
    let ids: Vec<u64> = v["nodes"].as_array().unwrap().iter().map(|n| n["id"].as_u64().unwrap()).collect();
    let (_, v) = call(&app, json_req("POST", "/api/v1/subgraph", Some(t), json!({"ids": ids}))).await;
    assert!(v["edges"].as_array().unwrap().iter().any(|e| e["kind"] == "DCSync"));
    let (_, v) = call(&app, get("/api/v1/queries", t)).await;
    let qs = v.as_array().unwrap();
    assert!(qs.len() >= 80);
    assert!(qs.iter().all(|q| q["id"].is_string() && q["tags"].is_array()));

    let (s, v) = call(&app, json_req("POST", "/api/v1/saved-queries", Some(t), json!({"name": "Admins", "query": "MATCH (u:User {admincount:true}) RETURN u"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["category"], "Custom");
    let sid = v["id"].as_str().unwrap().to_string();
    let (s, v) = call(&app, json_req("POST", "/api/v1/saved-queries", Some(t), json!({"name": "Broken", "query": "MATCH (u RETURN u"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], "syntax");
    let (s, v) = call(&app, json_req("PUT", &format!("/api/v1/saved-queries/{sid}"), Some(t), json!({"name": "Admins 2", "category": "Mine", "query": "MATCH (u:User) RETURN u LIMIT 5"}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["category"], "Mine");
    let (_, v) = call(&app, get("/api/v1/saved-queries", t)).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert!(data.join("saved_queries.json").exists());
    let (s, _) = call(&app, Request::builder().method("DELETE").uri(format!("/api/v1/saved-queries/{sid}")).header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);

    let (_, v) = call(&app, get(&format!("/api/v1/jobs/{job}"), t)).await;
    assert_eq!((v["phase"].as_str(), v["percent"].as_u64()), (Some("done"), Some(100)));

    let (_, v) = call(&app, get("/api/v1/tier0?top=5", t)).await;
    assert!(v["exposed_principals"].as_u64().unwrap() > 0);
    assert!(v["choke_points"].as_array().unwrap().len() <= 5);

    // Unified Tier Zero switch (settings.analysis.unified_tier0, default on).
    let unified = v["exposed_principals"].as_u64().unwrap();
    let (s, v) = call(&app, json_req("PUT", "/api/v1/settings", Some(t), json!({"analysis": {"unified_tier0": false}}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["settings"]["analysis"]["unified_tier0"], false);
    let (_, v) = call(&app, get("/api/v1/tier0?top=5", t)).await;
    assert!(v["exposed_principals"].as_u64().unwrap() < unified, "synced cloud users lose their AD paths");
    let (s, _) = call(&app, json_req("PUT", "/api/v1/settings", Some(t), json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&app, get("/api/v1/tier0?top=5", t)).await;
    assert_eq!(v["exposed_principals"].as_u64().unwrap(), unified);
    let (_, v) = call(&app, get("/api/v1/edge-kinds", t)).await;
    let sso = v.as_array().unwrap().iter().find(|k| k["name"] == "SeamlessSSO").unwrap();
    assert_eq!(sso["category"], "Hybrid");
    assert!(sso["count"].as_u64().unwrap() > 0 && sso["help"]["remediation"].is_string());

    // Marks persist and survive a re-ingest.
    let (s, v) = call(&app, json_req("POST", &format!("/api/v1/nodes/{svc_id}/marks"), Some(t), json!({"owned": true}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["owned"], true);
    let (_, v) = call(&app, json_req("POST", "/api/v1/ingest", Some(t), json!({}))).await;
    let job = v["job_id"].as_str().unwrap().to_string();
    for _ in 0..200 {
        let (_, v) = call(&app, get(&format!("/api/v1/jobs/{job}"), t)).await;
        if v["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (_, v) = call(&app, json_req("POST", "/api/v1/query", Some(t), json!({"query":"MATCH (o {owned:true}) RETURN o"}))).await;
    assert_eq!(v["nodes"][0]["name"], "SVC_BACKUP@SYNTH.LOCAL");

    let (s, _) = call(&app, Request::builder().method("DELETE").uri("/api/v1/uploads/..%2Fadmin_password").header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    assert_ne!(s, StatusCode::OK);
    assert!(data.join("admin_password").exists() || std::env::var("COPPERHOUND_ADMIN_PASSWORD").is_ok());

    let _ = std::fs::remove_dir_all(&data);
}

async fn ingest_and_wait(app: &axum::Router, t: &str) {
    let (_, v) = call(app, json_req("POST", "/api/v1/ingest", Some(t), json!({}))).await;
    let job = v["job_id"].as_str().unwrap().to_string();
    for _ in 0..400 {
        let (_, v) = call(app, get(&format!("/api/v1/jobs/{job}"), t)).await;
        if v["state"] == "done" {
            return;
        }
        assert_ne!(v["state"], "failed", "{v}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("ingest did not finish");
}

async fn wait_findings(app: &axum::Router, t: &str) -> Value {
    for _ in 0..400 {
        let resp = app.clone().oneshot(get("/api/v1/findings", t)).await.unwrap();
        let status = resp.status();
        let body: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        if status == StatusCode::OK {
            return body;
        }
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["status"], "computing");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("findings never became ready");
}

#[tokio::test(flavor = "multi_thread")]
async fn v12_findings_simulation_zones_posture() {
    let data = std::env::temp_dir().join(format!("ch-server-v12-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("uploads")).unwrap();
    // Tests share the process environment; use the same admin password as end_to_end_api.
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    ch_synth::generate(&ch_synth::SynthConfig { users: 800, computers: 160, groups: 80, seed: 9 }, &data.join("uploads")).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let token = v["token"].as_str().unwrap().to_string();
    let t = token.as_str();

    ingest_and_wait(&app, t).await;
    let f = wait_findings(&app, t).await;
    let list = f["findings"].as_array().unwrap();
    assert!(list.iter().any(|x| x["id"] == "dcsync-non-tier0"), "{f}");
    assert!(f["summary"]["critical"].as_u64().unwrap() >= 1);
    let first_snapshot = f["snapshot_id"].as_str().unwrap().to_string();

    // Reports: HTML (self-contained, script-free), Markdown, CSV.
    for (fmt, ctype, needle) in [("html", "text/html", "<h1>Attack path assessment</h1>"), ("md", "text/markdown", "## Executive summary"), ("csv", "text/csv", "finding_id,severity")] {
        let resp = app.clone().oneshot(get(&format!("/api/v1/report?format={fmt}&download=1"), t)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with(ctype));
        assert!(resp.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().contains(&format!(".{fmt}")));
        let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains(needle), "{fmt}: {}", &body[..body.len().min(400)]);
        if fmt == "html" {
            assert!(!body.contains("<script"));
            assert!(body.contains("dcsync-non-tier0") && body.contains("Remediation plan"));
        }
        if fmt == "csv" {
            assert!(body.lines().count() > 5);
        }
    }
    let (s, _) = call(&app, get("/api/v1/report?format=pdf", t)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, v) = call(&app, get("/api/v1/findings/privileged-sessions?limit=2", t)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert!(v["total"].as_u64().unwrap() >= 2);
    assert!(!v["graph"]["edges"].as_array().unwrap().is_empty());
    assert!(!v["remediation"].as_str().unwrap().is_empty());

    // What-if: removing every HasSession edge reduces exposure.
    let (s, v) = call(&app, json_req("POST", "/api/v1/simulate", Some(t), json!({"remove_kinds": ["HasSession"]}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["after"]["exposed_principals"].as_u64() < v["before"]["exposed_principals"].as_u64());
    assert!(v["reduction_percent"].as_f64().unwrap() > 0.0);
    let (s, _) = call(&app, json_req("POST", "/api/v1/simulate", Some(t), json!({"remove_kinds": ["Nope"]}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, v) = call(&app, json_req("POST", "/api/v1/remediation-plan", Some(t), json!({"steps": 3}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let steps = v["steps"].as_array().unwrap();
    assert!(!steps.is_empty());
    assert!(steps.last().unwrap()["cumulative_reduction_percent"].as_f64() >= steps[0]["cumulative_reduction_percent"].as_f64());
    assert!(steps[0]["node"]["name"].is_string());
    assert!(steps[0]["principals_cut"].as_u64().unwrap() > 0);
    assert!(steps[0]["edges"][0]["kind"].is_string());

    // Zones.
    let (_, v) = call(&app, get("/api/v1/zones", t)).await;
    assert_eq!(v[0]["id"], "tier0");
    assert!(v[0]["builtin"].as_bool().unwrap());
    let (s, v) = call(&app, json_req("POST", "/api/v1/zones", Some(t), json!({"name": "Workstations", "selector": "MATCH (c:Computer) WHERE c.name STARTS WITH 'WS' RETURN c"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let zid = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["member_count"], 157); // 160 computers - 2 DCs - AADC01
    assert!(v["color"].as_str().unwrap().starts_with('#'));
    let (_, v) = call(&app, get(&format!("/api/v1/zones/{zid}/members?limit=5"), t)).await;
    assert_eq!((v["total"].as_u64(), v["items"].as_array().unwrap().len()), (Some(157), 5));
    let (s, v) = call(&app, get(&format!("/api/v1/zones/{zid}/exposure?top=3"), t)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["exposed_principals"].as_u64().unwrap() > 0);
    let (s, v) = call(&app, json_req("POST", "/api/v1/zones", Some(t), json!({"name": "Bad", "selector": "MATCH (c RETURN c"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], "syntax");
    let (s, _) = call(&app, json_req("PUT", "/api/v1/zones/tier0", Some(t), json!({"name": "x", "selector": "MATCH (n) RETURN n"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = call(&app, json_req("POST", "/api/v1/remediation-plan", Some(t), json!({"zone": zid, "steps": 2}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = call(&app, get(&format!("/api/v1/zones/{zid}/members?limit=1"), t)).await;
    let ws_id = v["items"][0]["id"].as_u64().unwrap();
    let (_, v) = call(&app, json_req("POST", "/api/v1/zones/membership", Some(t), json!({"ids": [ws_id]}))).await;
    assert!(v[ws_id.to_string()].as_array().unwrap().iter().any(|z| z == &json!(zid)), "{v}");

    // Zone review: everything starts pending; revoked objects leave the zone.
    let (s, v) = call(&app, get(&format!("/api/v1/zones/{zid}/review?limit=3"), t)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["counts"]["pending"], 157);
    let oids: Vec<String> = v["items"].as_array().unwrap().iter().map(|r| r["node"]["objectid"].as_str().unwrap().to_lowercase()).collect();
    assert_eq!(oids.len(), 3);
    let (s, v) = call(&app, json_req("POST", &format!("/api/v1/zones/{zid}/review"), Some(t), json!({"objectids": [oids[0].clone(), oids[1].clone()], "status": "certified", "note": "owner confirmed"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = call(&app, json_req("POST", &format!("/api/v1/zones/{zid}/review"), Some(t), json!({"objectids": [oids[2].clone()], "status": "revoked"}))).await;
    assert_eq!(v["updated"], 1);
    let (_, v) = call(&app, get(&format!("/api/v1/zones/{zid}/review?status=certified"), t)).await;
    assert_eq!((v["counts"]["pending"].as_u64(), v["counts"]["certified"].as_u64(), v["counts"]["revoked"].as_u64()), (Some(154), Some(2), Some(1)));
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["items"][0]["decision"]["note"], "owner confirmed");
    assert_eq!(v["items"][0]["decision"]["by"], "admin");
    let (_, v) = call(&app, get(&format!("/api/v1/zones/{zid}/members?limit=1"), t)).await;
    assert_eq!(v["total"], 156, "revoked object left the zone");
    let (_, v) = call(&app, get("/api/v1/zones", t)).await;
    assert_eq!(v.as_array().unwrap().iter().find(|z| z["id"] == json!(zid)).unwrap()["member_count"], 156);
    // Back to pending restores membership.
    let (_, _) = call(&app, json_req("POST", &format!("/api/v1/zones/{zid}/review"), Some(t), json!({"objectids": [oids[2].clone()], "status": "pending"}))).await;
    let (_, v) = call(&app, get(&format!("/api/v1/zones/{zid}/members?limit=1"), t)).await;
    assert_eq!(v["total"], 157);
    let (s, _) = call(&app, json_req("POST", &format!("/api/v1/zones/{zid}/review"), Some(t), json!({"objectids": ["x"], "status": "maybe"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&app, get("/api/v1/zones/tier0/review", t)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&app, json_req("POST", "/api/v1/zones/nope/review", Some(t), json!({"objectids": ["x"], "status": "certified"}))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = call(&app, json_req("POST", "/api/v1/path", Some(t), json!({"from": "USER5@SYNTH.LOCAL", "to_zone": zid}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!v["hops"].as_array().unwrap().is_empty());
    let (_, v) = call(&app, get("/api/v1/findings/dcsync-non-tier0", t)).await;
    let svc = v["items"][0]["src"]["id"].as_u64().unwrap();
    let (_, v) = call(&app, get(&format!("/api/v1/findings-involving?node={svc}"), t)).await;
    assert!(v.as_array().unwrap().iter().any(|f| f["id"] == "dcsync-non-tier0"), "{v}");

    // Posture: drop the domains file (removes the DCSync grant) and re-ingest.
    let domains = std::fs::read_dir(data.join("uploads")).unwrap().filter_map(|e| e.ok()).find(|e| e.file_name().to_string_lossy().contains("domains")).unwrap();
    std::fs::remove_file(domains.path()).unwrap();
    ingest_and_wait(&app, t).await;
    let f2 = wait_findings(&app, t).await;
    let second_snapshot = f2["snapshot_id"].as_str().unwrap().to_string();
    assert_ne!(first_snapshot, second_snapshot);
    let (_, v) = call(&app, get("/api/v1/posture", t)).await;
    let hist = v.as_array().unwrap();
    assert_eq!(hist.len(), 2, "{v}");
    assert!(hist[0]["finding_counts"]["dcsync-non-tier0"].as_u64().unwrap() >= 1);
    let (s, v) = call(&app, get(&format!("/api/v1/posture/diff?from={first_snapshot}&to={second_snapshot}"), t)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let dc = v["findings"].as_array().unwrap().iter().find(|x| x["id"] == "dcsync-non-tier0").expect("dcsync diff");
    assert!(dc["removed"].as_u64().unwrap() >= 1);
    assert!(dc["removed_items"][0]["label"].as_str().unwrap().contains("DCSync"));
    // Per-finding history.
    let (s, v) = call(&app, get("/api/v1/findings/dcsync-non-tier0/history", t)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let pts = v["points"].as_array().unwrap();
    assert_eq!(pts.len(), 2);
    assert!(pts[0]["count"].as_u64().unwrap() >= 1);
    assert_eq!(pts[1]["count"], 0);
    assert!(v["latest_change"]["removed"].as_u64().unwrap() >= 1, "{v}");
    assert!(v["latest_change"]["removed_sample"][0].as_str().unwrap().contains("DCSync"));
    let (s, _) = call(&app, get("/api/v1/findings/nope/history", t)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&app, get("/api/v1/posture/diff?from=../../x&to=y", t)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&app, Request::builder().method("DELETE").uri(format!("/api/v1/posture/{first_snapshot}")).header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);

    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn upload_names_are_sanitized() {
    use ch_server::api::sanitize_upload_name as s;
    assert_eq!(s("20240101_BloodHound.zip").as_deref(), Some("20240101_BloodHound.zip"));
    assert_eq!(s("../../etc/passwd.json").as_deref(), Some("passwd.json"));
    assert_eq!(s("C:\\x\\evil name.json").as_deref(), Some("evil_name.json"));
    assert_eq!(s("notes.txt"), None);
    assert_eq!(s(".hidden.json"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn rbac_users_tokens_audit() {
    let data = std::env::temp_dir().join(format!("ch-server-rbac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let login = |u: &'static str, p: &'static str| {
        let app = app.clone();
        async move { call(&app, json_req("POST", "/api/v1/login", None, json!({"username":u,"password":p}))).await }
    };
    let (_, v) = login("admin", "test-password").await;
    assert_eq!(v["role"], "admin");
    let admin = v["token"].as_str().unwrap().to_string();

    // Create a viewer and an analyst.
    let (s, v) = call(&app, json_req("POST", "/api/v1/users", Some(&admin), json!({"username":"vera","password":"short","role":"viewer"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    for (u, r) in [("vera", "viewer"), ("andy", "analyst"), ("ulla", "uploader")] {
        let (s, v) = call(&app, json_req("POST", "/api/v1/users", Some(&admin), json!({"username":u,"password":"long-enough-pass","role":r}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (_, v) = login("vera", "long-enough-pass").await;
    let vera = v["token"].as_str().unwrap().to_string();
    let (_, v) = login("andy", "long-enough-pass").await;
    let andy = v["token"].as_str().unwrap().to_string();

    // Viewer: reads and analysis yes, changes no.
    let (s, v) = call(&app, get("/api/v1/me", &vera)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["permissions"]["modify"], false);
    let (s, _) = call(&app, json_req("POST", "/api/v1/query", Some(&vera), json!({"query":"MATCH (n) RETURN n"}))).await;
    assert_eq!(s, StatusCode::CONFLICT); // allowed, just no graph yet
    let zone = json!({"name":"Z","selector":"MATCH (n:User) RETURN n"});
    let (s, _) = call(&app, json_req("POST", "/api/v1/zones", Some(&vera), zone.clone())).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, json_req("POST", "/api/v1/ingest", Some(&vera), json!({}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Uploader: upload, ingest and jobs only; no graph access.
    let (_, v) = login("ulla", "long-enough-pass").await;
    let ulla = v["token"].as_str().unwrap().to_string();
    let (s, v) = call(&app, get("/api/v1/me", &ulla)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["role"], "uploader");
    assert_eq!((v["permissions"]["upload"].clone(), v["permissions"]["analyse"].clone()), (json!(true), json!(false)));
    let boundary = "UB";
    let part = r#"{"data":[],"meta":{"type":"users"}}"#;
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"u.json\"\r\nContent-Type: application/json\r\n\r\n{part}\r\n--{boundary}--\r\n"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/upload")
        .header(header::AUTHORIZATION, format!("Bearer {ulla}"))
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(body))
        .unwrap();
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, get("/api/v1/uploads", &ulla)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, get("/api/v1/jobs", &ulla)).await;
    assert_eq!(s, StatusCode::OK);
    for uri in ["/api/v1/stats", "/api/v1/search?q=a", "/api/v1/findings", "/api/v1/queries"] {
        let (s, _) = call(&app, get(uri, &ulla)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{uri}");
    }
    let (s, v) = call(&app, json_req("POST", "/api/v1/query", Some(&ulla), json!({"query":"MATCH (n) RETURN n"}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(v["error"].as_str().unwrap().contains("upload-only"));
    let (s, _) = call(&app, Request::builder().method("DELETE").uri("/api/v1/uploads/u.json").header(header::AUTHORIZATION, format!("Bearer {ulla}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "uploaders cannot delete uploads");
    let (s, v) = call(&app, json_req("POST", "/api/v1/me/tokens", Some(&ulla), json!({"name":"collector"}))).await;
    assert_eq!(s, StatusCode::OK, "uploaders can create API tokens for collectors: {v}");
    let (s, _) = call(&app, Request::builder().method("DELETE").uri("/api/v1/uploads/u.json").header(header::AUTHORIZATION, format!("Bearer {admin}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);

    // Analyst: changes yes, admin no.
    let (s, v) = call(&app, json_req("POST", "/api/v1/zones", Some(&andy), zone)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, get("/api/v1/users", &andy)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, get("/api/v1/audit", &andy)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // API token for automation.
    let (s, v) = call(&app, json_req("POST", "/api/v1/me/tokens", Some(&andy), json!({"name":"ci","expires_days":7}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let pat = v["token"].as_str().unwrap().to_string();
    let tid = v["id"].as_str().unwrap().to_string();
    let (s, v) = call(&app, get("/api/v1/me", &pat)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["username"], "andy");
    assert_eq!(v["via_token"], true);
    let (s, _) = call(&app, json_req("PUT", "/api/v1/me/password", Some(&pat), json!({"current_password":"long-enough-pass","new_password":"another-long-pass"}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Demotion applies immediately; disabling revokes sessions and tokens.
    let (s, _) = call(&app, json_req("PUT", "/api/v1/users/andy", Some(&admin), json!({"role":"viewer"}))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, json_req("POST", "/api/v1/zones", Some(&pat), json!({"name":"Z2","selector":"MATCH (n:User) RETURN n"}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, json_req("PUT", "/api/v1/users/andy", Some(&admin), json!({"disabled":true}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(call(&app, get("/api/v1/me", &andy)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&app, get("/api/v1/me", &pat)).await.0, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&app, json_req("DELETE", &format!("/api/v1/users/andy/tokens/{tid}"), Some(&admin), json!({}))).await;
    assert_eq!(s, StatusCode::OK);

    // The last admin cannot be removed or demoted.
    let (s, _) = call(&app, json_req("PUT", "/api/v1/users/admin", Some(&admin), json!({"role":"viewer"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Lockout after repeated failures.
    for _ in 0..5 {
        assert_eq!(login("vera", "wrong-password").await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(login("vera", "long-enough-pass").await.0, StatusCode::TOO_MANY_REQUESTS);

    // Audit trail.
    let (s, v) = call(&app, get("/api/v1/audit?limit=500", &admin)).await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<&str> = v["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    for want in ["login", "login-failed", "login-locked", "denied", "POST /zones", "PUT /users/{name}"] {
        assert!(actions.contains(&want), "missing {want} in {actions:?}");
    }
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn opengraph_custom_kinds_api() {
    let data = std::env::temp_dir().join(format!("ch-server-og-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("uploads")).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let og = json!({"metadata": {"source_kind": "Okta"}, "graph": {
        "nodes": [
            {"id": "okta-u1", "kinds": ["OktaUser"], "properties": {"name": "bob@example.com"}},
            {"id": "okta-app", "kinds": ["OktaApplication"], "properties": {"name": "payroll"}}],
        "edges": [{"kind": "OktaAssignedTo", "start": {"value": "okta-u1"}, "end": {"value": "okta-app"}}]}});
    std::fs::write(data.join("uploads").join("okta.json"), og.to_string()).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let t = t.as_str();
    ingest_and_wait(&app, t).await;

    let (_, v) = call(&app, get("/api/v1/search?q=bob&kind=OktaUser", t)).await;
    assert_eq!(v[0]["kind"], "OktaUser", "{v}");
    let (_, v) = call(&app, get("/api/v1/node-kinds", t)).await;
    let k = v.as_array().unwrap().iter().find(|k| k["name"] == "OktaApplication").expect("custom kind listed");
    assert_eq!(k["category"], "Custom");
    assert_eq!(k["count"], 1);
    let (s, v) = call(&app, json_req("POST", "/api/v1/query", Some(t), json!({"query": "MATCH p=(u:OktaUser)-[:OktaAssignedTo]->(a) RETURN p"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["nodes"].as_array().unwrap().iter().any(|n| n["kind"] == "OktaApplication"), "{v}");
    let (s, _) = call(&app, json_req("POST", "/api/v1/saved-queries", Some(t), json!({"name": "okta", "query": "MATCH (n:LaterKind) RETURN n"}))).await;
    assert_eq!(s, StatusCode::OK, "saved queries may use labels of graphs loaded later");
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn database_clear() {
    let data = std::env::temp_dir().join(format!("ch-server-clear-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("uploads")).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    ch_synth::generate(&ch_synth::SynthConfig { users: 200, computers: 40, groups: 20, seed: 5 }, &data.join("uploads")).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let t = t.as_str();
    ingest_and_wait(&app, t).await;

    // Data quality per domain / tenant.
    let (s, q) = call(&app, get("/api/v1/quality", t)).await;
    assert_eq!(s, StatusCode::OK, "{q}");
    let d = &q["domains"][0];
    assert_eq!(d["name"], "SYNTH.LOCAL");
    assert!(d["session_coverage"].as_f64().unwrap() > 0.0, "{d}");
    assert!(d["sources"].as_u64().unwrap() > 0);
    assert!(q["tenants"].is_array());

    let (_, v) = call(&app, get("/api/v1/search?q=USER1@&limit=1", t)).await;
    let id = v[0]["id"].as_u64().unwrap();
    let (s, _) = call(&app, json_req("POST", &format!("/api/v1/nodes/{id}/marks"), Some(t), json!({"owned": true}))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, json_req("POST", "/api/v1/zones", Some(t), json!({"name":"Z","selector":"MATCH (n:User) RETURN n"}))).await;
    assert_eq!(s, StatusCode::OK);

    let (s, _) = call(&app, json_req("POST", "/api/v1/database/clear", Some(t), json!({"marks": true}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "confirmation required");
    let (s, v) = call(&app, json_req("POST", "/api/v1/database/clear", Some(t), json!({"confirm": "DELETE", "marks": true, "zones": true}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["marks_cleared"], true);
    let (_, v) = call(&app, get(&format!("/api/v1/nodes/{id}"), t)).await;
    assert_eq!(v["owned"], false, "marks are no longer applied");
    let (_, v) = call(&app, get("/api/v1/zones", t)).await;
    assert!(v.as_array().unwrap().iter().all(|z| z["name"] != "Z"), "{v}");
    let (_, v) = call(&app, get("/api/v1/stats", t)).await;
    assert!(v["nodes"].as_u64().unwrap() > 0, "the graph stays loaded");

    // Remove every upload; rebuilding with nothing left unloads the graph.
    let (s, v) = call(&app, json_req("POST", "/api/v1/database/clear", Some(t), json!({"confirm": "DELETE", "uploads": "all", "rebuild": true}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["uploads_removed"].as_array().unwrap().len(), 5);
    let (_, v) = call(&app, get("/api/v1/uploads", t)).await;
    assert_eq!(v.as_array().unwrap().len(), 0);
    let (_, h) = call(&app, Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap()).await;
    assert_eq!(h["graph_loaded"], false, "{h}");
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn hmac_signed_requests() {
    use ch_server::hmac_auth::{canonical, sign};
    use sha2::{Digest, Sha256};
    let data = std::env::temp_dir().join(format!("ch-server-hmac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let (_, v) = call(&app, json_req("POST", "/api/v1/me/tokens", Some(&t), json!({"name":"signer"}))).await;
    let (token, id) = (v["token"].as_str().unwrap().to_string(), v["id"].as_str().unwrap().to_string());

    let hex = |b: &[u8]| Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect::<String>();
    let signed = |method: &str, uri: &str, body: &str, date: &str, content: Option<&str>| {
        let content = content.map(String::from).unwrap_or_else(|| hex(body.as_bytes()));
        let sig = sign(&token, &canonical(method, uri, date, &content));
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("CH-HMAC {id}"))
            .header("x-ch-date", date)
            .header("x-ch-content-sha256", content)
            .header("x-ch-signature", sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let now = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    let (s, v) = call(&app, signed("GET", "/api/v1/me", "", &now, None)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["username"], "admin");
    assert_eq!(v["via_token"], true);
    // Replay of the identical request.
    let (s, v) = call(&app, signed("GET", "/api/v1/me", "", &now, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    assert!(v["error"].as_str().unwrap().contains("replayed"));
    // Signed body.
    let body = r#"{"name":"q","query":"MATCH (n) RETURN n"}"#;
    let (s, v) = call(&app, signed("POST", "/api/v1/saved-queries", body, &now, None)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Body changed after signing.
    let mut req = signed("POST", "/api/v1/saved-queries", body, &now, Some(&hex(b"other")));
    *req.body_mut() = Body::from(body.to_string());
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(v["error"].as_str().unwrap().contains("body does not match"), "{v}");
    // Signature for another path.
    let mut req = signed("GET", "/api/v1/me", "", &now, Some(&format!("{:0>64}", "1")));
    *req.uri_mut() = "/api/v1/users".parse().unwrap();
    let (s, _) = call(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Old date.
    let old = humantime::format_rfc3339_seconds(std::time::SystemTime::now() - std::time::Duration::from_secs(900)).to_string();
    let (s, v) = call(&app, signed("GET", "/api/v1/me", "", &old, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(v["error"].as_str().unwrap().contains("5 minutes"), "{v}");
    // UNSIGNED-PAYLOAD is accepted (bodies too large to buffer, e.g. uploads).
    let (s, v) = call(&app, signed("GET", "/api/v1/uploads", "", &now, Some("UNSIGNED-PAYLOAD"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Revoked token.
    let (_, _) = call(&app, Request::builder().method("DELETE").uri(format!("/api/v1/me/tokens/{id}")).header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    let (s, _) = call(&app, signed("GET", "/api/v1/stats", "", &now, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn risk_acceptance() {
    let data = std::env::temp_dir().join(format!("ch-server-risk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("uploads")).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    ch_synth::generate(&ch_synth::SynthConfig { users: 400, computers: 80, groups: 40, seed: 9 }, &data.join("uploads")).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let t = t.as_str();
    ingest_and_wait(&app, t).await;
    let f = wait_findings(&app, t).await;
    // Environments: per-domain / per-tenant scoping partitions the items.
    let (s, envs) = call(&app, get("/api/v1/environments", t)).await;
    assert_eq!(s, StatusCode::OK, "{envs}");
    let envs = envs.as_array().unwrap().clone();
    assert!(envs.iter().any(|e| e["kind"] == "ad" && e["name"] == "SYNTH.LOCAL"), "{envs:?}");
    assert!(envs.iter().any(|e| e["kind"] == "tenant"), "{envs:?}");
    let total = |v: &Value, id: &str| v["findings"].as_array().unwrap().iter().find(|x| x["id"] == id).map_or(0, |x| x["count"].as_u64().unwrap());
    let fid = f["findings"][0]["id"].as_str().unwrap().to_string();
    let mut scoped_sum = 0;
    for e in &envs {
        let (s, v) = call(&app, get(&format!("/api/v1/findings?env={}", e["id"].as_str().unwrap()), t)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["environment"]["id"], e["id"]);
        scoped_sum += total(&v, &fid);
    }
    assert!(scoped_sum <= total(&f, &fid) && scoped_sum > 0, "{scoped_sum} vs {}", total(&f, &fid));
    let dom = envs.iter().find(|e| e["name"] == "SYNTH.LOCAL").unwrap()["id"].as_str().unwrap().to_string();
    let (s, v) = call(&app, get(&format!("/api/v1/findings?env={dom}"), t)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["findings"].as_array().unwrap().iter().all(|x| x["category"] != "Azure"), "AD scope has no Entra findings");
    let (s, _) = call(&app, get("/api/v1/findings?env=nope", t)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let resp = app.clone().oneshot(get(&format!("/api/v1/report?format=md&env={dom}"), t)).await.unwrap();
    let md = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(md.starts_with("# Attack path assessment — SYNTH.LOCAL"), "{}", &md[..80.min(md.len())]);

    let first = &f["findings"][0];
    let (id, sev) = (first["id"].as_str().unwrap().to_string(), first["severity"].as_str().unwrap().to_string());
    let open_before = f["summary"][&sev].as_u64().unwrap();
    assert_eq!(first["accepted"], Value::Null);

    let (s, _) = call(&app, json_req("PUT", &format!("/api/v1/findings/{id}/acceptance"), Some(t), json!({"reason": ""}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a reason is required");
    let (s, _) = call(&app, json_req("PUT", "/api/v1/findings/nope/acceptance", Some(t), json!({"reason": "x"}))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = call(&app, json_req("PUT", &format!("/api/v1/findings/{id}/acceptance"), Some(t), json!({"reason": "compensating control", "expires_days": 30}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["acceptance"]["accepted_by"], "admin");
    let f = wait_findings(&app, t).await;
    let fi = f["findings"].as_array().unwrap().iter().find(|x| x["id"] == id.as_str()).unwrap();
    assert_eq!(fi["accepted"]["reason"], "compensating control");
    assert_eq!(f["summary"][&sev].as_u64().unwrap(), open_before - 1);
    assert_eq!(f["summary_all"][&sev].as_u64().unwrap(), open_before);
    assert_eq!(f["accepted_count"], 1);
    let resp = app.clone().oneshot(get("/api/v1/report?format=md", t)).await.unwrap();
    let md = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(md.contains("### Accepted risks") && md.contains("compensating control"), "{}", &md[..md.len().min(400)]);
    let (_, v) = call(&app, get("/api/v1/findings/accepted", t)).await;
    assert_eq!(v[0]["id"], id.as_str());
    assert_eq!(v[0]["active"], true);

    let (s, _) = call(&app, Request::builder().method("DELETE").uri(format!("/api/v1/findings/{id}/acceptance")).header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    let f = wait_findings(&app, t).await;
    assert_eq!(f["summary"][&sev].as_u64().unwrap(), open_before);
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn collector_clients() {
    let data = std::env::temp_dir().join(format!("ch-server-coll-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let admin = v["token"].as_str().unwrap().to_string();

    let (s, _) = call(&app, json_req("POST", "/api/v1/collectors", Some(&admin), json!({"name":"Corp DC","kind":"nope"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut req = json_req("POST", "/api/v1/collectors", Some(&admin), json!({"name":"Corp DC","kind":"sharphound","interval_hours":24}));
    req.headers_mut().insert(header::HOST, "ch.example.com".parse().unwrap());
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let token = v["token"].as_str().unwrap().to_string();
    let id = v["collector"]["id"].as_str().unwrap().to_string();
    assert_eq!(v["collector"]["username"], "collector-corp-dc");
    assert_eq!(v["collector"]["status"], "never");
    let script = v["commands"]["script"].as_str().unwrap();
    assert!(script.contains(&token) && script.contains("http://ch.example.com/api/v1/upload"), "{script}");

    // The collector's token is upload-only.
    let (s, _) = call(&app, get("/api/v1/stats", &token)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let boundary = "CB";
    let part = r#"{"data":[],"meta":{"type":"users"}}"#;
    let body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"c.json\"\r\nContent-Type: application/json\r\n\r\n{part}\r\n--{boundary}--\r\n");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(body))
        .unwrap();
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = call(&app, get("/api/v1/collectors", &admin)).await;
    assert_eq!(v[0]["status"], "ok", "{v}");
    assert_eq!(v[0]["uploads"], 1);
    assert_eq!(v[0]["last_files"][0], "c.json");

    let (s, _) = call(&app, Request::builder().method("DELETE").uri(format!("/api/v1/collectors/{id}")).header(header::AUTHORIZATION, format!("Bearer {admin}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, get("/api/v1/me", &token)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "account and token are gone");
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_factor_sign_in() {
    use ch_server::mfa::{base32_decode, code_at, STEP_SECS};
    let data = std::env::temp_dir().join(format!("ch-server-mfa-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let login = |otp: Option<&str>| {
        let mut b = json!({"username":"admin","password":"test-password"});
        if let Some(o) = otp {
            b["otp"] = json!(o);
        }
        json_req("POST", "/api/v1/login", None, b)
    };
    let (_, v) = call(&app, login(None)).await;
    let t = v["token"].as_str().unwrap().to_string();
    let step = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / STEP_SECS;
    let code = |secret: &str, s: u64| format!("{:06}", code_at(&base32_decode(secret).unwrap(), s));

    let (s, v) = call(&app, json_req("POST", "/api/v1/me/mfa/setup", Some(&t), json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let secret = v["secret"].as_str().unwrap().to_string();
    assert!(v["qr_svg"].as_str().unwrap().contains("<svg") && v["uri"].as_str().unwrap().starts_with("otpauth://totp/"));
    let (s, _) = call(&app, json_req("POST", "/api/v1/me/mfa/enable", Some(&t), json!({"code": "000000"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let now = step();
    let (s, v) = call(&app, json_req("POST", "/api/v1/me/mfa/enable", Some(&t), json!({"code": code(&secret, now)}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let recovery: Vec<String> = v["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(recovery.len(), 10);

    // Password alone is no longer enough.
    let (s, v) = call(&app, login(None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["mfa_required"], true);
    let (s, _) = call(&app, login(Some("123456"))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The enrolment step's code was used; the next step's works, once.
    let next = code(&secret, now + 1);
    let (s, v) = call(&app, login(Some(&next))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, login(Some(&next))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "codes are single-use");
    // Recovery code, once.
    let (s, _) = call(&app, login(Some(&recovery[0].to_ascii_uppercase()))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, login(Some(&recovery[0]))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, v) = call(&app, get("/api/v1/me/mfa", &t)).await;
    assert_eq!((v["enabled"].clone(), v["recovery_codes_left"].clone()), (json!(true), json!(9)));
    let (_, v) = call(&app, get("/api/v1/users", &t)).await;
    assert_eq!(v["users"][0]["mfa"], true);
    // Disable with a recovery code, then the password works alone again.
    let (s, v) = call(&app, json_req("POST", "/api/v1/me/mfa/disable", Some(&t), json!({"code": recovery[1]}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, login(None)).await;
    assert_eq!(s, StatusCode::OK);
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_and_restore() {
    let data = std::env::temp_dir().join(format!("ch-server-backup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let login = |app: axum::Router| async move {
        let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
        v["token"].as_str().unwrap().to_string()
    };
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let t = login(app.clone()).await;
    let (s, _) = call(&app, json_req("POST", "/api/v1/zones", Some(&t), json!({"name":"Crown jewels","selector":"MATCH (n:User) RETURN n"}))).await;
    assert_eq!(s, StatusCode::OK);
    let resp = app.clone().oneshot(get("/api/v1/backup", &t)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/zip");
    let zip_bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    assert!(zip_bytes.starts_with(b"PK"));

    // Change state after the backup.
    let (_, z) = call(&app, get("/api/v1/zones", &t)).await;
    let zid = z.as_array().unwrap().iter().find(|z| z["name"] == "Crown jewels").unwrap()["id"].as_str().unwrap().to_string();
    let del = Request::builder().method("DELETE").uri(format!("/api/v1/zones/{zid}")).header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap();
    assert_eq!(call(&app, del).await.0, StatusCode::OK);

    // Restore: staged, applied on restart.
    let boundary = "RB";
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"backup\"; filename=\"b.zip\"\r\nContent-Type: application/zip\r\n\r\n").into_bytes();
    body.extend_from_slice(&zip_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/restore")
        .header(header::AUTHORIZATION, format!("Bearer {t}"))
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(body))
        .unwrap();
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["restart_required"], true);
    let (_, z) = call(&app, get("/api/v1/zones", &t)).await;
    assert!(!z.as_array().unwrap().iter().any(|z| z["name"] == "Crown jewels"), "not applied before restart");
    drop(app);
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let t = login(app.clone()).await;
    let (_, z) = call(&app, get("/api/v1/zones", &t)).await;
    assert!(z.as_array().unwrap().iter().any(|z| z["name"] == "Crown jewels"), "{z}");
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn bloodhound_compatible_upload_api() {
    use ch_server::compat::bh_signature;
    let data = std::env::temp_dir().join(format!("ch-server-v2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    // BloodHound-style login.
    let (s, v) = call(&app, json_req("POST", "/api/v2/login", None, json!({"login_method":"secret","username":"admin","secret":"test-password"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let session = v["data"]["session_token"].as_str().unwrap().to_string();
    let (_, v) = call(&app, json_req("POST", "/api/v1/me/tokens", Some(&session), json!({"name":"bh"}))).await;
    let (id, key, bearer) = (v["id"].as_str().unwrap().to_string(), v["bloodhound_key"].as_str().unwrap().to_string(), v["token"].as_str().unwrap().to_string());

    let signed = |method: &str, uri: &str, body: Vec<u8>, ctype: &str, key: &str| {
        let date = humantime::format_rfc3339_micros(std::time::SystemTime::now()).to_string().replace('Z', "+00:00");
        let sig = bh_signature(key.as_bytes(), method, uri, &date, &body);
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("bhesignature {id}"))
            .header("RequestDate", date)
            .header("Signature", sig)
            .header(header::CONTENT_TYPE, ctype)
            .body(Body::from(body))
            .unwrap()
    };
    let (s, v) = call(&app, signed("POST", "/api/v2/file-upload/start", vec![], "application/json", &key)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let job = v["data"]["id"].as_u64().unwrap();
    let file = br#"{"data":[],"meta":{"type":"users","count":0,"version":6}}"#.to_vec();
    let req = signed("POST", &format!("/api/v2/file-upload/{job}"), file.clone(), "application/json", &key);
    let replay = signed("POST", &format!("/api/v2/file-upload/{job}"), file.clone(), "application/json", &key);
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, replay).await;
    assert_eq!(s, StatusCode::OK, "BloodHound signatures cover the hour only; repeats are accepted like BloodHound does");
    // Wrong key.
    let (s, _) = call(&app, signed("POST", &format!("/api/v2/file-upload/{job}"), file.clone(), "application/json", "nope")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Bodies over 8 MiB are spooled to disk while the signature is checked;
    // the spool is gone afterwards whether the signature was good or not.
    let spools = || std::fs::read_dir(&data).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with(".bhsig-")).count();
    let mut big = br#"{"data":["#.to_vec();
    big.resize(9 << 20, b' ');
    big.extend_from_slice(br#"],"meta":{"type":"users","count":0,"version":6}}"#);
    let (s, _) = call(&app, signed("POST", &format!("/api/v2/file-upload/{job}"), big.clone(), "application/json", "nope")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(spools(), 0, "spool left after a rejected signature");
    let (s, v) = call(&app, signed("POST", &format!("/api/v2/file-upload/{job}"), big, "application/json", &key)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(spools(), 0, "spool left after the upload");
    // Bearer API token works too.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v2/file-upload/{job}"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/zip")
        .body(Body::from(b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec()))
        .unwrap();
    let (s, v) = call(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["data"]["file"].as_str().unwrap().ends_with(".zip"));
    let (s, v) = call(&app, signed("POST", &format!("/api/v2/file-upload/{job}/end"), vec![], "application/json", &key)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["data"]["ingest_job"].is_string(), "{v}");
    let (_, v) = call(&app, get("/api/v1/uploads", &session)).await;
    assert!(v.as_array().unwrap().len() >= 2, "{v}");
    tokio::time::sleep(std::time::Duration::from_millis(30)).await; // a new RequestDate, not a replay
    let (s, v) = call(&app, signed("POST", &format!("/api/v2/file-upload/{job}"), file, "application/json", &key)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "job already ended: {v}");
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn ldap_collector_targets() {
    let data = std::env::temp_dir().join(format!("ch-server-ldapc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let put = |b: Value| json_req("PUT", "/api/v1/collect/ldap", Some(&t), b);
    let (s, _) = call(&app, put(json!({"name":"corp","url":"ldap://dc01","bind_dn":"svc@corp.local","password":"x"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "plain LDAP needs StartTLS or an explicit opt-in");
    let (s, v) = call(&app, put(json!({"name":"corp","url":"ldaps://dc01.corp.local","bind_dn":"svc@corp.local","password":"s3cret","interval_hours":12}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v.get("password").is_none() && v["password_set"] == true, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    // Update without a password keeps it.
    let (s, v) = call(&app, put(json!({"id": id, "name":"corp dc","url":"ldaps://dc01.corp.local","bind_dn":"svc@corp.local","interval_hours":24}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["password_set"], true);
    assert_eq!(v["name"], "corp dc");
    let (_, v) = call(&app, get("/api/v1/collect/ldap", &t)).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert!(!std::fs::read_to_string(data.join("ldap_collect.json")).unwrap().is_empty());
    // Unreachable DC: the test reports the error instead of hanging.
    let (_, v) = call(&app, json_req("POST", &format!("/api/v1/collect/ldap/{id}/test"), Some(&t), json!({}))).await;
    assert_eq!(v["ok"], false, "{v}");
    let (s, _) = call(&app, Request::builder().method("DELETE").uri(format!("/api/v1/collect/ldap/{id}")).header(header::AUTHORIZATION, format!("Bearer {t}")).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn kind_styles() {
    let data = std::env::temp_dir().join(format!("ch-server-styles-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let t = v["token"].as_str().unwrap().to_string();
    let (s, _) = call(&app, json_req("PUT", "/api/v1/kind-styles", Some(&t), json!({"GHUser": {"color": "red"}}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = call(&app, json_req("PUT", "/api/v1/kind-styles", Some(&t), json!({"GHUser": {"color": "#ff8800", "icon": "🐙"}, "Empty": {}}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v.get("Empty").is_none(), "empty styles are dropped");
    // BloodHound custom-nodes API merges colours.
    let (s, _) = call(&app, json_req("POST", "/api/v2/custom-nodes", Some(&t), json!({"custom_types": {"GHRepository": {"icon": {"type": "font-awesome", "name": "box", "color": "#00AA55"}}}}))).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&app, get("/api/v1/kind-styles", &t)).await;
    assert_eq!(v["GHUser"]["icon"], "🐙");
    assert_eq!(v["GHRepository"]["color"], "#00AA55");
    assert_eq!(v["GHRepository"]["icon_name"], "box");
    let _ = std::fs::remove_dir_all(&data);
}

#[tokio::test(flavor = "multi_thread")]
async fn network_conduits() {
    let data = std::env::temp_dir().join(format!("ch-server-net-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    let up = data.join("uploads");
    std::fs::create_dir_all(&up).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    ch_synth::generate(&ch_synth::SynthConfig { users: 400, computers: 80, groups: 40, seed: 21 }, &up).unwrap();
    // Every computer in zone SERVERS (OpenGraph enrichment).
    let comps: Value = serde_json::from_slice(&std::fs::read(up.join("synth_computers.json")).unwrap()).unwrap();
    let nodes: Vec<Value> = comps["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| json!({"id": c["ObjectIdentifier"], "kinds": ["Computer"], "properties": {"net_zone": "SERVERS"}}))
        .collect();
    let n_hosts = nodes.len();
    std::fs::write(up.join("zones.json"), json!({"graph": {"nodes": nodes}}).to_string()).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let token = v["token"].as_str().unwrap().to_string();
    let t = token.as_str();
    ingest_and_wait(&app, t).await;

    let (s, v) = call(&app, get("/api/v1/network", t)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["conduits"].is_null());
    let path_req = json!({"from": "USER1@SYNTH.LOCAL", "to_tier0": true, "network": true});
    let (s, _) = call(&app, json_req("POST", "/api/v1/path", Some(t), path_req.clone())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "network path without conduits");

    let (s, v) = call(&app, json_req("PUT", "/api/v1/network", Some(t), json!({"attacker_zone": "IT", "conduits": [{"from": "IT", "to": "SERVERS", "services": ["telnet"]}]}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    // No conduit into SERVERS: remote access and session theft on computers are blocked.
    let (s, v) = call(&app, json_req("PUT", "/api/v1/network", Some(t), json!({"attacker_zone": "IT", "conduits": []}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let zones = v["zones"].as_array().unwrap();
    assert!(zones.iter().any(|z| z["name"] == "SERVERS" && z["hosts"] == n_hosts as u64), "{v}");
    let (s, closed) = call(&app, get("/api/v1/network/exposure", t)).await;
    assert_eq!(s, StatusCode::OK, "{closed}");
    assert!(closed["network_exposed"].as_u64().unwrap() < closed["identity_exposed"].as_u64().unwrap(), "{closed}");

    // Everything open: network exposure equals identity exposure.
    let (s, _) = call(&app, json_req("PUT", "/api/v1/network", Some(t), json!({"attacker_zone": "IT", "conduits": [{"from": "*", "to": "*", "services": ["*"]}]}))).await;
    assert_eq!(s, StatusCode::OK);
    let (_, open) = call(&app, get("/api/v1/network/exposure", t)).await;
    assert_eq!(open["network_exposed"], open["identity_exposed"], "{open}");
    let (s, v) = call(&app, json_req("POST", "/api/v1/path", Some(t), path_req)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["network"], true);

    let (s, v) = call(&app, json_req("DELETE", "/api/v1/network", Some(t), json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["conduits"].is_null());
    let _ = std::fs::remove_dir_all(&data);
}
