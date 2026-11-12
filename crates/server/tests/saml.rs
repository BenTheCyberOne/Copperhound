//! SAML sign-on end to end: login redirect, signed response at the ACS,
//! session exchange, replay and browser binding.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use ch_server::samlxml::exc_c14n;
use ch_server::state::AppState;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use tower::ServiceExt;

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/saml/");
const IDP: &str = "https://idp.example.com/saml";
const SP: &str = "https://copperhound.example.com/api/v1/auth/saml/metadata";
const ACS: &str = "https://copperhound.example.com/api/v1/auth/saml/acs";

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn json_req(method: &str, uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn iso(t: std::time::SystemTime) -> String {
    humantime::format_rfc3339_seconds(t).to_string()
}

/// A response to `request_id` with a signed assertion (signed here with the
/// fixture IdP key; canonicalisation is checked against libxml2 in samlxml).
fn signed_response(request_id: &str, name: &str, groups: &[&str]) -> String {
    let now = std::time::SystemTime::now();
    let (issued, until, before) =
        (iso(now), iso(now + std::time::Duration::from_secs(300)), iso(now - std::time::Duration::from_secs(60)));
    let values: String = groups.iter().map(|g| format!("<saml:AttributeValue>{g}</saml:AttributeValue>")).collect();
    let assertion = format!(
        r#"<saml:Assertion ID="_as-{request_id}" Version="2.0" IssueInstant="{issued}"><saml:Issuer>{IDP}</saml:Issuer><saml:Subject><saml:NameID>{name}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{until}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{until}"><saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="groups">{values}</saml:Attribute></saml:AttributeStatement></saml:Assertion>"#
    );
    let wrap = |a: &str| {
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-{request_id}" Version="2.0" IssueInstant="{issued}" Destination="{ACS}" InResponseTo="{request_id}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{a}</samlp:Response>"#
        )
    };
    // Digest of the assertion in context.
    let unsigned = wrap(&assertion);
    let doc = roxmltree::Document::parse(&unsigned).unwrap();
    let a = doc.descendants().find(|n| n.has_tag_name((ch_server::samlxml::NS_SAML, "Assertion"))).unwrap();
    let digest = STANDARD.encode(Sha256::digest(exc_c14n(&unsigned, &a, &[], false, None).as_bytes()));
    let signed_info = format!(
        r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_as-{request_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    let with_si = assertion.replacen(
        "</saml:Issuer>",
        &format!(r#"</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>SIG</ds:SignatureValue></ds:Signature>"#),
        1,
    );
    let doc_xml = wrap(&with_si);
    let doc = roxmltree::Document::parse(&doc_xml).unwrap();
    let si = doc.descendants().find(|n| n.has_tag_name((ch_server::samlxml::NS_DSIG, "SignedInfo"))).unwrap();
    let si_c = exc_c14n(&doc_xml, &si, &[], false, None);
    let key = RsaPrivateKey::from_pkcs8_pem(&std::fs::read_to_string(format!("{FIX}idp_key.pem")).unwrap()).unwrap();
    let sig = SigningKey::<Sha256>::new(key).sign(si_c.as_bytes());
    doc_xml.replacen("SIG", &STANDARD.encode(sig.to_bytes()), 1)
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish()
}

#[tokio::test(flavor = "multi_thread")]
async fn saml_sign_in_end_to_end() {
    let data = std::env::temp_dir().join(format!("ch-server-saml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();
    std::env::set_var("COPPERHOUND_ADMIN_PASSWORD", "test-password");
    let (st, _) = AppState::new(data.clone(), None).unwrap();
    let app = ch_server::router(st);
    let (_, _, v) = send(&app, json_req("POST", "/api/v1/login", None, json!({"username":"admin","password":"test-password"}))).await;
    let admin = v["token"].as_str().unwrap().to_string();

    let md = std::fs::read_to_string(format!("{FIX}idp_metadata.xml")).unwrap();
    let cfg = json!({"enabled": true, "idp_metadata": md, "sp_entity_id": SP, "acs_url": ACS, "groups_attribute": "groups",
                     "role_mapping": {"admin": [], "analyst": ["CH-Analysts"], "viewer": []}, "default_role": "deny"});
    let (s, _, v) = send(&app, json_req("PUT", "/api/v1/settings/saml", Some(&admin), cfg)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["idp"]["entity_id"], IDP);
    let (s, _, _) = send(&app, json_req("PUT", "/api/v1/settings/saml", Some(&admin), json!({"enabled": true, "idp_metadata": "<x/>"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "invalid metadata is refused");
    let (_, _, v) = send(&app, Request::builder().uri("/api/v1/auth/providers").body(Body::empty()).unwrap()).await;
    assert_eq!(v["saml"]["enabled"], true);

    // Login redirect.
    let login = |rt: &str| Request::builder().uri(format!("/api/v1/auth/saml/login?return_to={rt}")).header(header::HOST, "copperhound.example.com").body(Body::empty()).unwrap();
    let (s, h, _) = send(&app, login("/%23/x")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let loc = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    assert!(loc.as_str().starts_with("https://idp.example.com/sso/redirect?"));
    let q: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&STANDARD.decode(&q["SAMLRequest"]).unwrap()[..]).read_to_string(&mut xml).unwrap();
    let req_doc = roxmltree::Document::parse(&xml).unwrap();
    let request_id = req_doc.root_element().attribute("ID").unwrap().to_string();
    assert_eq!(req_doc.root_element().attribute("AssertionConsumerServiceURL"), Some(ACS));
    let cookie = h[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    assert!(h[header::SET_COOKIE].to_str().unwrap().contains("SameSite=None; Secure"));

    let resp = STANDARD.encode(signed_response(&request_id, "carol@example.com", &["CH-Analysts"]));
    let acs = |body: String, cookie: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/auth/saml/acs")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie.to_string())
            .body(Body::from(body))
            .unwrap()
    };
    // Wrong browser: the cookie does not match.
    let body = form(&[("SAMLResponse", &resp), ("RelayState", &q["RelayState"])]);
    let (s, h, _) = send(&app, acs(body.clone(), "ch_saml=other")).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(h[header::LOCATION].to_str().unwrap().contains("sso_error=state"));

    // The RelayState was consumed: start again and complete.
    let (_, h, _) = send(&app, login("/")).await;
    let loc = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    let q: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&STANDARD.decode(&q["SAMLRequest"]).unwrap()[..]).read_to_string(&mut xml).unwrap();
    let request_id = roxmltree::Document::parse(&xml).unwrap().root_element().attribute("ID").unwrap().to_string();
    let cookie2 = h[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    assert_ne!(cookie, cookie2);
    let resp = STANDARD.encode(signed_response(&request_id, "carol@example.com", &["CH-Analysts"]));
    let body = form(&[("SAMLResponse", &resp), ("RelayState", &q["RelayState"])]);
    let (s, h, _) = send(&app, acs(body.clone(), &cookie2)).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let to = h[header::LOCATION].to_str().unwrap().to_string();
    let code = to.split("code=").nth(1).unwrap_or_else(|| panic!("sign-in failed: {to}"));
    // Redeemed by the same browser: it holds the exchange cookie set with the code.
    let xc = h
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next())
        .find(|c| c.starts_with("ch_oidc=") && c.len() > 8)
        .expect("exchange cookie")
        .to_string();
    let mut req = json_req("POST", "/api/v1/auth/oidc/exchange", None, json!({"code": code}));
    req.headers_mut().insert(header::COOKIE, xc.parse().unwrap());
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["username"], "carol@example.com");
    assert_eq!(v["role"], "analyst");

    // Replaying the same POST fails (RelayState already used).
    let (_, h, _) = send(&app, acs(body, &cookie2)).await;
    assert!(h[header::LOCATION].to_str().unwrap().contains("sso_error=state"));

    // Unmapped user is denied.
    let (_, h, _) = send(&app, login("/")).await;
    let loc = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    let q: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&STANDARD.decode(&q["SAMLRequest"]).unwrap()[..]).read_to_string(&mut xml).unwrap();
    let request_id = roxmltree::Document::parse(&xml).unwrap().root_element().attribute("ID").unwrap().to_string();
    let cookie3 = h[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    let resp = STANDARD.encode(signed_response(&request_id, "dave@example.com", &["Staff"]));
    let (_, h, _) = send(&app, acs(form(&[("SAMLResponse", &resp), ("RelayState", &q["RelayState"])]), &cookie3)).await;
    assert!(h[header::LOCATION].to_str().unwrap().contains("sso_error=denied"));

    // SP metadata.
    let resp = app.clone().oneshot(Request::builder().uri("/api/v1/auth/saml/metadata").body(Body::empty()).unwrap()).await.unwrap();
    let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(body.contains(ACS) && body.contains(SP), "{body}");
    let _ = std::fs::remove_dir_all(&data);
}
