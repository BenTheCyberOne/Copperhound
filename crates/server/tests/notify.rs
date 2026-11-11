//! Notifications, scheduled reports and change alerts, end to end against an
//! in-process webhook receiver.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
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

async fn ingest_and_wait(app: &axum::Router, t: &str) {
    let (_, v) = call(app, json_req("POST", "/api/v1/ingest", Some(t), json!({}))).await;
    let job = v["job_id"].as_str().unwrap().to_string();
    for _ in 0..600 {
        let (_, v) = call(app, get(&format!("/api/v1/jobs/{job}"), t)).await;
        if v["state"] == "done" {
            return;
        }
        assert_ne!(v["state"], "failed", "{v}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("ingest did not finish");
}

type Received = Arc<Mutex<Vec<(HeaderMap, Vec<u8>)>>>;

/// In-process webhook receiver: records `(headers, body)` of every POST.
async fn mock_receiver() -> (String, Received) {
    let got: Received = Default::default();
    let got2 = got.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let got = got2.clone();
            async move {
                got.lock().push((headers, body.to_vec()));
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), got)
}

fn hmac_hex(secret: &str, body: &[u8]) -> String {
    use hmac::Mac;
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    m.update(body);
    m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

async fn wait_until<T, Fut: std::future::Future<Output = Option<T>>>(mut f: impl FnMut() -> Fut, what: &str) -> T {
    for _ in 0..600 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn notifications_schedules_alerts() {
    let data = std::env::temp_dir().join(format!("ch-server-notify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("uploads")).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    ch_synth::generate(&ch_synth::SynthConfig { users: 300, computers: 60, groups: 40, seed: 5 }, &data.join("uploads")).unwrap();
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let admin = v["token"].as_str().unwrap().to_string();
    let t = admin.as_str();
    let (url, got) = mock_receiver().await;

    // Channels: secrets are write-only.
    let (s, v) = call(
        &app,
        json_req(
            "PUT",
            "/api/v1/notify/channels",
            Some(t),
            json!({"channels": [
                {"name": "hook", "type": "webhook", "url": url, "secret": "topsecret"},
                {"name": "slack", "type": "slack", "url": "https://hooks.slack.com/services/T0/B0/XYZTOKEN", "enabled": false},
                {"name": "mail", "type": "email", "smtp_host": "smtp.example.com", "smtp_username": "u", "smtp_password": "pw-123",
                 "email_from": "ch@example.com", "email_to": ["sec@example.com"]}
            ]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let text = v.to_string();
    for secret in ["topsecret", "XYZTOKEN", "pw-123", url.as_str()] {
        assert!(!text.contains(secret), "secret {secret} leaked: {text}");
    }
    let chans = v["channels"].as_array().unwrap();
    assert_eq!(chans[0]["secret_set"], true);
    assert_eq!(chans[0]["url_set"], true);
    assert_eq!(chans[1]["url_hint"], "https://hooks.slack.com/…");
    assert_eq!(chans[2]["smtp_password_set"], true);
    assert_eq!(chans[2]["smtp_port"], 587);
    let hook_id = chans[0]["id"].as_str().unwrap().to_string();
    let (_, v2) = call(&app, get("/api/v1/notify/channels", t)).await;
    assert_eq!(v2, v);
    // Re-saving the GET shape (no secrets) keeps the stored secrets.
    let (s, v3) = call(&app, json_req("PUT", "/api/v1/notify/channels", Some(t), json!({"channels": v["channels"]}))).await;
    assert_eq!(s, StatusCode::OK, "{v3}");
    assert_eq!(v3, v);
    let (s, _) = call(
        &app,
        json_req("PUT", "/api/v1/notify/channels", Some(t), json!({"channels": [{"name":"x","type":"webhook","url":"gopher://x/"}]})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Test-send: JSON with a valid HMAC signature over the exact body.
    let (s, v) = call(&app, json_req("POST", &format!("/api/v1/notify/channels/{hook_id}/test"), Some(t), json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    {
        let g = got.lock();
        let (h, body) = g.last().unwrap();
        assert_eq!(h["x-copperhound-signature"].to_str().unwrap(), format!("sha256={}", hmac_hex("topsecret", body)));
        assert_eq!(h["x-copperhound-event"], "test");
        let j: Value = serde_json::from_slice(body).unwrap();
        assert_eq!((j["event"].as_str(), j["source"].as_str()), (Some("test"), Some("copperhound")));
    }

    // RBAC: analysts can read alert history but not configuration.
    let (s, _) = call(
        &app,
        json_req("POST", "/api/v1/users", Some(t), json!({"username":"ana","password":"long-enough-pass","role":"analyst"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&app, json_req("POST", "/api/v1/login", None, json!({"username":"ana","password":"long-enough-pass"}))).await;
    let ana = v["token"].as_str().unwrap().to_string();
    assert_eq!(call(&app, get("/api/v1/alerts", &ana)).await.0, StatusCode::OK);
    assert_eq!(call(&app, get("/api/v1/notify/channels", &ana)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(call(&app, get("/api/v1/schedules", &ana)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(call(&app, get("/api/v1/alerts/rules", &ana)).await.0, StatusCode::FORBIDDEN);

    // Alert rules: only "new principals gained a path to Tier Zero".
    let (s, v) = call(
        &app,
        json_req(
            "PUT",
            "/api/v1/alerts/rules",
            Some(t),
            json!({
                "enabled": true, "channels": [hook_id], "grade_worse": false, "exposure_increase_points": null,
                "new_finding_severities": [], "new_tier0_principals_min": 1, "choke_points_changed": false, "choke_points_top": 10
            }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, json_req("PUT", "/api/v1/alerts/rules", Some(t), json!({"enabled": true, "channels": ["nope"]}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // First ingest establishes the baseline: no alert.
    ingest_and_wait(&app, t).await;
    let state = data.join("alert_state.json");
    wait_until(|| async { state.exists().then_some(()) }, "alert state").await;
    let (_, v) = call(&app, get("/api/v1/alerts", t)).await;
    assert_eq!(v["alerts"].as_array().unwrap().len(), 0);

    // Schedule: create, run now, the webhook receives the summary.
    let (s, v) = call(
        &app,
        json_req(
            "POST",
            "/api/v1/schedules",
            Some(t),
            json!({"name": "Weekly", "when": {"kind": "weekly", "weekday": "Monday", "at": "07:00"}, "format": "md", "channels": [hook_id]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["when"]["weekday"], "mon");
    assert!(v["next_run"].as_str().unwrap().ends_with("T07:00:00Z"), "{v}");
    let sid = v["id"].as_str().unwrap().to_string();
    let (s, _) = call(
        &app,
        json_req("POST", "/api/v1/schedules", Some(t), json!({"name": "bad", "when": {"kind":"daily","at":"25:00"}, "channels": [hook_id]})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let before = got.lock().len();
    let (s, _) = call(&app, json_req("POST", &format!("/api/v1/schedules/{sid}/run"), Some(t), json!({}))).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let body = wait_until(|| async { got.lock().get(before).map(|x| x.1.clone()) }, "scheduled report").await;
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(j["event"], "report");
    assert!(["A", "B", "C", "D", "F"].contains(&j["data"]["grade"].as_str().unwrap()), "{j}");
    assert!(j["data"]["exposure_percent"].is_number());
    let sched = wait_until(
        || async {
            let v = call(&app, get("/api/v1/schedules", t)).await.1;
            (v["schedules"][0]["last_status"] == "ok").then_some(v)
        },
        "schedule status",
    )
    .await;
    assert_eq!(sched["schedules"][0]["last_deliveries"][0]["ok"], true);
    let (s, v) = call(
        &app,
        json_req(
            "PUT",
            &format!("/api/v1/schedules/{sid}"),
            Some(t),
            json!({"name": "Six-hourly", "when": {"kind": "interval", "hours": 6}, "channels": [hook_id], "enabled": false}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["enabled"], false);
    assert_eq!(v["last_status"], "ok");

    // Second ingest with different data: new principals reach Tier Zero → alert.
    for e in std::fs::read_dir(data.join("uploads")).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    ch_synth::generate(&ch_synth::SynthConfig { users: 500, computers: 80, groups: 50, seed: 11 }, &data.join("uploads")).unwrap();
    let before = got.lock().len();
    ingest_and_wait(&app, t).await;
    let body = wait_until(
        || async { got.lock().iter().skip(before).find(|x| x.0["x-copperhound-event"] == "alert").map(|x| x.1.clone()) },
        "alert webhook",
    )
    .await;
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(j["data"]["triggers"][0]["rule"], "new_tier0_principals", "{j}");
    assert!(j["data"]["new_tier0_principals"].as_u64().unwrap() >= 1);
    // Each newly exposed principal in the sample comes with a shortest path
    // into Tier Zero: a connected chain from it, ending on a Tier Zero object,
    // as long as the path the API finds now.
    let paths = j["data"]["new_paths"].as_array().unwrap();
    assert!(!paths.is_empty(), "{j}");
    for p in paths {
        let hops = p["hops"].as_array().unwrap();
        assert!(!hops.is_empty(), "{p}");
        assert_eq!(hops[0]["src"], p["objectid"]);
        for w in hops.windows(2) {
            assert_eq!(w[0]["dst"], w[1]["src"], "{p}");
        }
        let (_, last) = call(&app, json_req("POST", "/api/v1/nodes/resolve", Some(t), json!({"objectids": [hops.last().unwrap()["dst"]]}))).await;
        assert_eq!(last[0]["tier0"], true, "{p}");
        let (s, v) = call(&app, json_req("POST", "/api/v1/path", Some(t), json!({"from": p["objectid"], "to_zone": "tier0"}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["hops"].as_array().unwrap().len(), hops.len(), "shortest length for {}", p["name"]);
    }
    assert!(j["text"].as_str().unwrap().contains("\nPath: "), "{}", j["text"]);
    let alerts = wait_until(
        || async {
            let v = call(&app, get("/api/v1/alerts", &ana)).await.1;
            (!v["alerts"].as_array().unwrap().is_empty()).then_some(v)
        },
        "alert history",
    )
    .await;
    assert_eq!(alerts["alerts"][0]["deliveries"][0]["ok"], true);

    // Deleting a schedule; configuration changes are audited.
    let (s, _) = call(&app, json_req("DELETE", &format!("/api/v1/schedules/{sid}"), Some(t), json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&app, get("/api/v1/audit?limit=200", t)).await;
    let text = v.to_string();
    assert!(text.contains("/notify/channels") && text.contains("/alerts/rules") && text.contains("/schedules/{id}"), "{text}");
    let _ = std::fs::remove_dir_all(&data);
}
