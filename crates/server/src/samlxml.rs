//! SAML 2.0 XML processing for the service provider (`saml.rs`): exclusive
//! XML canonicalisation, XML-DSig verification of responses, response and
//! assertion validation, IdP metadata and AuthnRequest construction.
//!
//! Pure functions over `roxmltree` documents (no libxml2 / xmlsec), written to
//! fail closed:
//!
//! * Documents with a DTD are rejected (no entity expansion, no XXE).
//! * Duplicate `ID` attributes are rejected, and a signature counts only for
//!   the element it is a direct child of, whose `ID` its single `Reference`
//!   must name. The assertion that is then read is that same element (or the
//!   single assertion inside a signed response), never one found again by ID:
//!   this defeats XML signature wrapping.
//! * Only exclusive C14N (with or without comments), the enveloped-signature
//!   transform, SHA-256/384/512 digests and RSA PKCS#1 v1.5 with
//!   SHA-256/384/512 are accepted. SHA-1 is refused.
//! * Keys come only from the configured IdP certificates, never from the
//!   response's `KeyInfo`.
//! * Encrypted assertions are not supported (refused).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use roxmltree::{Document, Node, NodeType, ParsingOptions};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, HashSet};

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// Largest SAML message accepted (decoded).
pub const MAX_XML_BYTES: usize = 1 << 20;

pub type Result<T> = std::result::Result<T, String>;

pub fn parse(xml: &str) -> Result<Document<'_>> {
    if xml.len() > MAX_XML_BYTES {
        return Err("SAML message too large".into());
    }
    let opts = ParsingOptions { allow_dtd: false, ..ParsingOptions::default() };
    Document::parse_with_options(xml, opts).map_err(|e| format!("malformed XML: {e}"))
}

fn is(n: &Node, ns: &str, name: &str) -> bool {
    n.is_element() && n.tag_name().namespace() == Some(ns) && n.tag_name().name() == name
}

fn children<'a, 'i>(n: &Node<'a, 'i>, ns: &'a str, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> + use<'a, 'i> {
    n.children().filter(move |c| is(c, ns, name))
}

fn child<'a, 'i>(n: &Node<'a, 'i>, ns: &'a str, name: &'a str) -> Option<Node<'a, 'i>> {
    children(n, ns, name).next()
}

/// Text content of an element (concatenated text children), trimmed.
fn text(n: &Node) -> String {
    n.children().filter(|c| c.is_text()).filter_map(|c| c.text()).collect::<String>().trim().to_string()
}

// ------------------------------------------------------------------ C14N

/// Raw qualified name of an element, read from the source text.
fn elem_qname<'i>(src: &'i str, n: &Node) -> &'i str {
    let start = n.range().start + 1; // skip '<'
    let rest = &src[start..];
    let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').unwrap_or(rest.len());
    &rest[..end]
}

fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map(|(p, _)| p).unwrap_or("")
}

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// In-scope namespace URI of `prefix` ("" = default) at element `n`.
fn ns_uri<'a>(n: &Node<'a, '_>, prefix: &str) -> Option<&'a str> {
    n.namespaces().find(|ns| ns.name().unwrap_or("") == prefix).map(|ns| ns.uri())
}

struct C14n<'s> {
    src: &'s str,
    comments: bool,
    /// Prefixes treated inclusively (`InclusiveNamespaces PrefixList`; "" = `#default`).
    inclusive: Vec<String>,
    /// Subtree left out (the enveloped signature).
    skip: Option<roxmltree::NodeId>,
}

impl C14n<'_> {
    fn element(&self, n: &Node, rendered: &BTreeMap<String, String>, out: &mut String) {
        let qname = elem_qname(self.src, n);
        // Visibly utilised prefixes: the element's, its attributes', plus the
        // inclusive list.
        let mut used: Vec<String> = vec![prefix_of(qname).to_string()];
        let attrs: Vec<(String, &str, &str, &str)> = n
            .attributes()
            .map(|a| {
                let q = &self.src[a.range_qname()];
                (a.namespace().unwrap_or("").to_string(), a.name(), q, a.value())
            })
            .collect();
        for (_, _, q, _) in &attrs {
            let p = prefix_of(q);
            if !p.is_empty() && p != "xml" {
                used.push(p.to_string());
            }
        }
        for p in &self.inclusive {
            if ns_uri(n, p).is_some() || p.is_empty() {
                used.push(p.clone());
            }
        }
        used.sort();
        used.dedup();
        let mut next = rendered.clone();
        let mut decls: Vec<(String, String)> = Vec::new();
        for p in used {
            if p == "xml" {
                continue;
            }
            let uri = ns_uri(n, &p).unwrap_or("").to_string();
            let prev = rendered.get(&p).map(String::as_str).unwrap_or("");
            if p.is_empty() {
                // Default namespace: emit when it differs from the output
                // ancestor's (an empty one only undoes a rendered default).
                if uri != prev {
                    decls.push((p.clone(), uri.clone()));
                }
            } else if rendered.get(&p) != Some(&uri) {
                decls.push((p.clone(), uri.clone()));
            }
            next.insert(p, uri);
        }
        out.push('<');
        out.push_str(qname);
        for (p, uri) in &decls {
            if p.is_empty() {
                out.push_str(" xmlns=\"");
            } else {
                out.push_str(" xmlns:");
                out.push_str(p);
                out.push_str("=\"");
            }
            esc_attr(uri, out);
            out.push('"');
        }
        let mut sorted = attrs;
        sorted.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
        for (_, _, q, v) in &sorted {
            out.push(' ');
            out.push_str(q);
            out.push_str("=\"");
            esc_attr(v, out);
            out.push('"');
        }
        out.push('>');
        for c in n.children() {
            if Some(c.id()) == self.skip {
                continue;
            }
            match c.node_type() {
                NodeType::Element => self.element(&c, &next, out),
                NodeType::Text => esc_text(c.text().unwrap_or(""), out),
                NodeType::Comment if self.comments => {
                    out.push_str("<!--");
                    out.push_str(c.text().unwrap_or(""));
                    out.push_str("-->");
                }
                NodeType::PI => {
                    if let Some(pi) = c.pi() {
                        out.push_str("<?");
                        out.push_str(pi.target);
                        if let Some(v) = pi.value {
                            out.push(' ');
                            out.push_str(v);
                        }
                        out.push_str("?>");
                    }
                }
                _ => {}
            }
        }
        out.push_str("</");
        out.push_str(qname);
        out.push('>');
    }
}

/// Exclusive canonical form of the subtree rooted at `n`, leaving out `skip`.
pub fn exc_c14n(src: &str, n: &Node, inclusive: &[String], comments: bool, skip: Option<roxmltree::NodeId>) -> String {
    let c = C14n { src, comments, inclusive: inclusive.to_vec(), skip };
    let mut out = String::new();
    c.element(n, &BTreeMap::new(), &mut out);
    out
}

// ------------------------------------------------------------ signatures

fn digest(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Sha256::digest(data).to_vec(),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Sha384::digest(data).to_vec(),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Sha512::digest(data).to_vec(),
        "http://www.w3.org/2000/09/xmldsig#sha1" => return Err("SHA-1 digests are not accepted".into()),
        a => return Err(format!("unsupported digest algorithm {a}")),
    })
}

fn verify_rsa(alg: &str, key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<bool> {
    let s = Signature::try_from(sig).map_err(|_| "malformed signature value".to_string())?;
    Ok(match alg {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => VerifyingKey::<Sha256>::new(key.clone()).verify(msg, &s).is_ok(),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => VerifyingKey::<Sha384>::new(key.clone()).verify(msg, &s).is_ok(),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => VerifyingKey::<Sha512>::new(key.clone()).verify(msg, &s).is_ok(),
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => return Err("RSA-SHA1 signatures are not accepted".into()),
        a => return Err(format!("unsupported signature algorithm {a}")),
    })
}

fn c14n_alg(n: &Node) -> Result<(bool, Vec<String>)> {
    let alg = n.attribute("Algorithm").unwrap_or("");
    let comments = match alg {
        ALG_EXC_C14N => false,
        ALG_EXC_C14N_COMMENTS => true,
        a => return Err(format!("unsupported canonicalization {a} (only exclusive C14N)")),
    };
    let inclusive = children(n, NS_EXC_C14N, "InclusiveNamespaces")
        .filter_map(|i| i.attribute("PrefixList"))
        .flat_map(|l| l.split_whitespace().map(|p| if p == "#default" { String::new() } else { p.to_string() }).collect::<Vec<_>>())
        .collect();
    Ok((comments, inclusive))
}

fn b64(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(clean).map_err(|_| "invalid base64".to_string())
}

/// Verifies the `ds:Signature` that is a direct child of `signed`. Ok(true)
/// when it is valid for one of `keys`; Err for malformed or unsupported ones.
pub fn verify_enveloped(src: &str, signed: &Node, keys: &[RsaPublicKey]) -> Result<bool> {
    let sigs: Vec<Node> = children(signed, NS_DSIG, "Signature").collect();
    let sig = match sigs.as_slice() {
        [] => return Ok(false),
        [s] => *s,
        _ => return Err("more than one signature on one element".into()),
    };
    let id = signed.attribute("ID").ok_or("signed element has no ID")?;
    let si = child(&sig, NS_DSIG, "SignedInfo").ok_or("Signature without SignedInfo")?;
    let cm = child(&si, NS_DSIG, "CanonicalizationMethod").ok_or("SignedInfo without CanonicalizationMethod")?;
    let (si_comments, si_incl) = c14n_alg(&cm)?;
    let sm = child(&si, NS_DSIG, "SignatureMethod").and_then(|m| m.attribute("Algorithm")).ok_or("SignedInfo without SignatureMethod")?;
    let refs: Vec<Node> = children(&si, NS_DSIG, "Reference").collect();
    let [r] = refs.as_slice() else {
        return Err("signature must have exactly one Reference".into());
    };
    if r.attribute("URI") != Some(&format!("#{id}")) {
        return Err("signature Reference does not point at the signed element".into());
    }
    let mut enveloped = false;
    let (mut comments, mut incl) = (false, Vec::new());
    let mut c14n_seen = false;
    if let Some(ts) = child(r, NS_DSIG, "Transforms") {
        for t in children(&ts, NS_DSIG, "Transform") {
            match t.attribute("Algorithm").unwrap_or("") {
                ALG_ENVELOPED => enveloped = true,
                ALG_EXC_C14N | ALG_EXC_C14N_COMMENTS => {
                    (comments, incl) = c14n_alg(&t)?;
                    c14n_seen = true;
                }
                a => return Err(format!("unsupported transform {a}")),
            }
        }
    }
    if !enveloped {
        return Err("signature is not enveloped".into());
    }
    if !c14n_seen {
        // Default canonicalisation of a node-set reference is inclusive C14N,
        // which is not supported.
        return Err("reference has no exclusive C14N transform".into());
    }
    let dm = child(r, NS_DSIG, "DigestMethod").and_then(|m| m.attribute("Algorithm")).ok_or("Reference without DigestMethod")?;
    let dv = child(r, NS_DSIG, "DigestValue").map(|v| text(&v)).ok_or("Reference without DigestValue")?;
    let canon = exc_c14n(src, signed, &incl, comments, Some(sig.id()));
    if digest(dm, canon.as_bytes())? != b64(&dv)? {
        return Ok(false);
    }
    let sv = child(&sig, NS_DSIG, "SignatureValue").map(|v| text(&v)).ok_or("Signature without SignatureValue")?;
    let sv = b64(&sv)?;
    let si_canon = exc_c14n(src, &si, &si_incl, si_comments, None);
    for k in keys {
        if verify_rsa(sm, k, si_canon.as_bytes(), &sv)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// RSA public key of a PEM or base64-DER X.509 certificate.
pub fn cert_key(cert: &str) -> Result<RsaPublicKey> {
    use x509_cert::der::{Decode, Encode};
    let body: String = cert
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = STANDARD.decode(body).map_err(|_| "certificate is not valid base64 / PEM".to_string())?;
    let c = x509_cert::Certificate::from_der(&der).map_err(|e| format!("invalid certificate: {e}"))?;
    let spki = c.tbs_certificate.subject_public_key_info.to_der().map_err(|e| format!("invalid certificate key: {e}"))?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|_| "certificate key is not an RSA key (only RSA is supported)".to_string())
}

/// SHA-256 fingerprint of a certificate (hex, colon-separated), for display.
pub fn cert_fingerprint(cert: &str) -> Option<String> {
    let body: String = cert.lines().filter(|l| !l.starts_with("-----")).collect::<String>().chars().filter(|c| !c.is_whitespace()).collect();
    let der = STANDARD.decode(body).ok()?;
    Some(Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

// -------------------------------------------------------------- metadata

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IdpMetadata {
    pub entity_id: String,
    /// SingleSignOnService with the HTTP-Redirect binding.
    pub sso_url: String,
    /// Signing certificates (base64 DER).
    pub certs: Vec<String>,
}

pub fn parse_idp_metadata(xml: &str) -> Result<IdpMetadata> {
    let doc = parse(xml)?;
    let root = doc.root_element();
    let ed = if is(&root, NS_MD, "EntityDescriptor") {
        root
    } else if is(&root, NS_MD, "EntitiesDescriptor") {
        let eds: Vec<Node> = root.descendants().filter(|n| is(n, NS_MD, "EntityDescriptor") && child(n, NS_MD, "IDPSSODescriptor").is_some()).collect();
        match eds.as_slice() {
            [e] => *e,
            [] => return Err("metadata has no identity provider".into()),
            _ => return Err("metadata describes several identity providers; paste the one to use".into()),
        }
    } else {
        return Err("not SAML metadata (no EntityDescriptor)".into());
    };
    let entity_id = ed.attribute("entityID").unwrap_or("").trim().to_string();
    if entity_id.is_empty() {
        return Err("EntityDescriptor has no entityID".into());
    }
    let idp = child(&ed, NS_MD, "IDPSSODescriptor").ok_or("metadata has no IDPSSODescriptor")?;
    let sso_url = children(&idp, NS_MD, "SingleSignOnService")
        .find(|s| s.attribute("Binding") == Some(BINDING_REDIRECT))
        .and_then(|s| s.attribute("Location"))
        .ok_or("IdP has no HTTP-Redirect SingleSignOnService")?
        .trim()
        .to_string();
    let mut certs = Vec::new();
    for kd in children(&idp, NS_MD, "KeyDescriptor").filter(|k| k.attribute("use").is_none_or(|u| u == "signing")) {
        for c in kd.descendants().filter(|n| is(n, NS_DSIG, "X509Certificate")) {
            let t: String = text(&c).chars().filter(|c| !c.is_whitespace()).collect();
            if !t.is_empty() && !certs.contains(&t) {
                certs.push(t);
            }
        }
    }
    if certs.is_empty() {
        return Err("IdP metadata has no signing certificate".into());
    }
    Ok(IdpMetadata { entity_id, sso_url, certs })
}

/// SP metadata for the IdP administrator.
pub fn sp_metadata(entity_id: &str, acs_url: &str) -> String {
    let mut e = String::new();
    esc_attr(entity_id, &mut e);
    let mut a = String::new();
    esc_attr(acs_url, &mut a);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{NS_MD}" entityID="{e}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="{NS_SAMLP}">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:AssertionConsumerService Binding="{BINDING_POST}" Location="{a}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#
    )
}

/// AuthnRequest XML (HTTP-Redirect binding, unsigned).
pub fn authn_request(id: &str, issue_instant: &str, destination: &str, acs_url: &str, sp_entity_id: &str) -> String {
    let e = |s: &str| {
        let mut o = String::new();
        esc_attr(s, &mut o);
        o
    };
    let mut issuer = String::new();
    esc_text(sp_entity_id, &mut issuer);
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="{BINDING_POST}"><saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>"#,
        e(id),
        e(issue_instant),
        e(destination),
        e(acs_url)
    )
}

/// Raw-DEFLATE + base64 for the HTTP-Redirect binding.
pub fn deflate_b64(xml: &str) -> String {
    use flate2::write::DeflateEncoder;
    use std::io::Write;
    let mut enc = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(xml.as_bytes());
    STANDARD.encode(enc.finish().unwrap_or_default())
}

// -------------------------------------------------------------- response

/// What the response must match.
pub struct Expect<'a> {
    pub idp_entity_id: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    /// ID of the AuthnRequest this answers (IdP-initiated sign-in is refused).
    pub request_id: &'a str,
    pub keys: &'a [RsaPublicKey],
    /// Unix seconds.
    pub now: i64,
    pub skew_secs: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    pub assertion_id: String,
    pub name_id: String,
    /// Attribute name → values.
    pub attributes: BTreeMap<String, Vec<String>>,
    /// Assertion expiry (Conditions NotOnOrAfter), unix seconds, for the replay cache.
    pub not_on_or_after: i64,
}

fn time(s: &str) -> Result<i64> {
    let t = humantime::parse_rfc3339_weak(s.trim().trim_end_matches('Z')).map_err(|_| format!("invalid time {s:?}"))?;
    Ok(t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0))
}

/// Verify and validate a base64-decoded SAML Response.
pub fn verify_response(xml: &str, x: &Expect) -> Result<Verified> {
    let doc = parse(xml)?;
    let root = doc.root_element();
    if !is(&root, NS_SAMLP, "Response") {
        return Err("not a SAML Response".into());
    }
    // Duplicate IDs make reference resolution ambiguous (signature wrapping).
    let mut ids = HashSet::new();
    for n in doc.descendants().filter(|n| n.is_element()) {
        for a in n.attributes().filter(|a| a.name() == "ID" || a.name() == "Id") {
            if !ids.insert(a.value()) {
                return Err("duplicate ID attribute in response".into());
            }
        }
    }
    let status = child(&root, NS_SAMLP, "Status")
        .and_then(|s| child(&s, NS_SAMLP, "StatusCode"))
        .and_then(|c| c.attribute("Value"))
        .unwrap_or("");
    if status != STATUS_SUCCESS {
        return Err(format!("identity provider returned status {status:?}"));
    }
    if let Some(d) = root.attribute("Destination") {
        if d != x.acs_url {
            return Err(format!("response Destination {d:?} is not this service's ACS URL"));
        }
    }
    if root.attribute("InResponseTo") != Some(x.request_id) {
        return Err("response does not answer our sign-in request (InResponseTo)".into());
    }
    if let Some(iss) = child(&root, NS_SAML, "Issuer") {
        if text(&iss) != x.idp_entity_id {
            return Err(format!("response issuer {:?} is not the configured IdP", text(&iss)));
        }
    }
    if child(&root, NS_SAML, "EncryptedAssertion").is_some() {
        return Err("encrypted assertions are not supported; disable assertion encryption at the IdP".into());
    }
    let assertions: Vec<Node> = children(&root, NS_SAML, "Assertion").collect();
    let [a] = assertions.as_slice() else {
        return Err(format!("response must contain exactly one assertion (found {})", assertions.len()));
    };
    let a = *a;
    // Signatures anywhere else are not ours to interpret.
    let response_signed = verify_enveloped(xml, &root, x.keys)?;
    let assertion_signed = verify_enveloped(xml, &a, x.keys)?;
    let has_sig = |n: &Node| child(n, NS_DSIG, "Signature").is_some();
    if (has_sig(&root) && !response_signed) || (has_sig(&a) && !assertion_signed) {
        return Err("invalid signature".into());
    }
    if !response_signed && !assertion_signed {
        return Err("neither the response nor the assertion is signed".into());
    }

    let issuer = child(&a, NS_SAML, "Issuer").map(|i| text(&i)).unwrap_or_default();
    if issuer != x.idp_entity_id {
        return Err(format!("assertion issuer {issuer:?} is not the configured IdP"));
    }
    let subject = child(&a, NS_SAML, "Subject").ok_or("assertion has no Subject")?;
    let name_id = child(&subject, NS_SAML, "NameID").map(|n| text(&n)).unwrap_or_default();
    let bearer_ok = children(&subject, NS_SAML, "SubjectConfirmation")
        .filter(|sc| sc.attribute("Method") == Some(CM_BEARER))
        .filter_map(|sc| child(&sc, NS_SAML, "SubjectConfirmationData"))
        .any(|d| {
            let not_after_ok = d.attribute("NotOnOrAfter").and_then(|t| time(t).ok()).is_some_and(|t| x.now < t + x.skew_secs);
            let recipient_ok = d.attribute("Recipient") == Some(x.acs_url);
            let irt_ok = d.attribute("InResponseTo").is_none_or(|i| i == x.request_id);
            let nb_ok = d.attribute("NotBefore").is_none();
            not_after_ok && recipient_ok && irt_ok && nb_ok
        });
    if !bearer_ok {
        return Err("no valid bearer SubjectConfirmation (recipient, expiry or request mismatch)".into());
    }
    let cond = child(&a, NS_SAML, "Conditions").ok_or("assertion has no Conditions")?;
    if let Some(nb) = cond.attribute("NotBefore") {
        if x.now + x.skew_secs < time(nb)? {
            return Err("assertion is not yet valid".into());
        }
    }
    let not_on_or_after = match cond.attribute("NotOnOrAfter") {
        Some(t) => {
            let t = time(t)?;
            if x.now >= t + x.skew_secs {
                return Err("assertion has expired".into());
            }
            t
        }
        None => x.now + 300,
    };
    let restrictions: Vec<Node> = children(&cond, NS_SAML, "AudienceRestriction").collect();
    if restrictions.is_empty() {
        return Err("assertion has no AudienceRestriction".into());
    }
    // Every restriction must include us (each one narrows the audience).
    for r in &restrictions {
        if !children(r, NS_SAML, "Audience").any(|au| text(&au) == x.sp_entity_id) {
            return Err(format!("assertion audience does not include {:?}", x.sp_entity_id));
        }
    }
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for st in children(&a, NS_SAML, "AttributeStatement") {
        for at in children(&st, NS_SAML, "Attribute") {
            let Some(name) = at.attribute("Name") else { continue };
            let vals = attributes.entry(name.to_string()).or_default();
            for v in children(&at, NS_SAML, "AttributeValue") {
                let t = text(&v);
                if !t.is_empty() {
                    vals.push(t);
                }
            }
            if let Some(f) = at.attribute("FriendlyName").filter(|f| *f != name) {
                let copy = attributes[name].clone();
                attributes.entry(f.to_string()).or_default().extend(copy);
            }
        }
    }
    let assertion_id = a.attribute("ID").ok_or("assertion has no ID")?.to_string();
    Ok(Verified { assertion_id, name_id, attributes, not_on_or_after })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n_of(xml: &str, path: &[&str], incl: &[&str]) -> String {
        let doc = parse(xml).unwrap();
        let mut n = doc.root_element();
        for p in path {
            n = n.children().find(|c| c.is_element() && c.tag_name().name() == *p).unwrap();
        }
        let incl: Vec<String> = incl.iter().map(|s| s.to_string()).collect();
        exc_c14n(xml, &n, &incl, false, None)
    }

    #[test]
    fn exclusive_c14n_basics() {
        // Attribute order, namespace pruning, escaping, empty elements,
        // inherited namespaces rendered where used.
        let xml = "<r:Root xmlns:r=\"urn:r\" xmlns:x=\"urn:x\" xmlns:u=\"urn:unused\"><r:Child b=\"2\" a=\"1&amp;&lt;&quot;\" x:z=\"3\"><x:E/>t&gt;\r\n<!-- c --></r:Child></r:Root>";
        assert_eq!(
            c14n_of(xml, &["Child"], &[]),
            "<r:Child xmlns:r=\"urn:r\" xmlns:x=\"urn:x\" a=\"1&amp;&lt;&quot;\" b=\"2\" x:z=\"3\"><x:E></x:E>t&gt;\n</r:Child>"
        );
        // Default namespace and undeclaring it.
        let xml = "<Root xmlns=\"urn:d\"><A><B xmlns=\"\"/></A></Root>";
        assert_eq!(c14n_of(xml, &["A"], &[]), "<A xmlns=\"urn:d\"><B xmlns=\"\"></B></A>");
        // Inclusive prefix list renders a namespace only used in values.
        let xml = "<r xmlns:xs=\"urn:xs\" xmlns:xsi=\"urn:xsi\"><v xsi:type=\"xs:string\">s</v></r>";
        assert_eq!(c14n_of(xml, &["v"], &[]), "<v xmlns:xsi=\"urn:xsi\" xsi:type=\"xs:string\">s</v>");
        assert_eq!(c14n_of(xml, &["v"], &["xs"]), "<v xmlns:xs=\"urn:xs\" xmlns:xsi=\"urn:xsi\" xsi:type=\"xs:string\">s</v>");
    }

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/saml/");

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIX}{name}")).unwrap()
    }

    /// Fixtures are signed by libxml2's exclusive C14N (lxml) — see gen.py.
    fn check(name: &str) -> Result<Verified> {
        let md = parse_idp_metadata(&fixture("idp_metadata.xml")).unwrap();
        let keys: Vec<RsaPublicKey> = md.certs.iter().map(|c| cert_key(c).unwrap()).collect();
        let now = time("2026-01-01T00:01:00Z").unwrap();
        let x = Expect {
            idp_entity_id: &md.entity_id,
            sp_entity_id: "https://copperhound.example.com/api/v1/auth/saml/metadata",
            acs_url: "https://copperhound.example.com/api/v1/auth/saml/acs",
            request_id: "_req-0123456789abcdef",
            keys: &keys,
            now,
            skew_secs: 60,
        };
        verify_response(&fixture(name), &x)
    }

    #[test]
    fn metadata() {
        let md = parse_idp_metadata(&fixture("idp_metadata.xml")).unwrap();
        assert_eq!(md.entity_id, "https://idp.example.com/saml");
        assert_eq!(md.sso_url, "https://idp.example.com/sso/redirect");
        assert_eq!(md.certs.len(), 1, "encryption keys are ignored");
        assert!(cert_key(&fixture("idp_cert.pem")).is_ok());
    }

    #[test]
    fn accepts_signed_responses() {
        for f in ["resp_assertion_signed.xml", "resp_response_signed.xml", "resp_both_signed.xml"] {
            let v = check(f).unwrap_or_else(|e| panic!("{f}: {e}"));
            assert_eq!(v.name_id, "alice@example.com", "{f}");
            assert_eq!(v.assertion_id, "_a-1");
            assert!(v.attributes["email"] == vec!["alice@example.com".to_string()] && v.attributes.contains_key("mail"));
        }
        let v = check("resp_assertion_signed.xml").unwrap();
        assert_eq!(v.attributes["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"], vec!["CH-Admins", "Staff"]);
    }

    #[test]
    fn rejects_bad_responses() {
        let err = |f: &str| check(f).expect_err(f);
        assert_eq!(err("resp_wrong_key.xml"), "invalid signature");
        assert_eq!(err("resp_tampered.xml"), "invalid signature");
        assert_eq!(err("resp_wrapped.xml"), "neither the response nor the assertion is signed");
        assert!(err("resp_sha1.xml").contains("SHA-1"));
        assert_eq!(err("resp_duplicate_id.xml"), "duplicate ID attribute in response");
    }

    #[test]
    fn validates_conditions() {
        let md = parse_idp_metadata(&fixture("idp_metadata.xml")).unwrap();
        let keys: Vec<RsaPublicKey> = md.certs.iter().map(|c| cert_key(c).unwrap()).collect();
        let xml = fixture("resp_assertion_signed.xml");
        let base = Expect {
            idp_entity_id: &md.entity_id,
            sp_entity_id: "https://copperhound.example.com/api/v1/auth/saml/metadata",
            acs_url: "https://copperhound.example.com/api/v1/auth/saml/acs",
            request_id: "_req-0123456789abcdef",
            keys: &keys,
            now: time("2026-01-01T00:01:00Z").unwrap(),
            skew_secs: 60,
        };
        assert!(verify_response(&xml, &base).is_ok());
        let later = Expect { now: time("2026-01-01T00:07:00Z").unwrap(), ..base };
        assert!(verify_response(&xml, &later).is_err(), "expired");
        let other_req = Expect { request_id: "_other", now: base.now, ..later };
        assert!(verify_response(&xml, &other_req).unwrap_err().contains("InResponseTo"));
        let other_aud = Expect { request_id: base.request_id, sp_entity_id: "https://other", ..other_req };
        assert!(verify_response(&xml, &other_aud).unwrap_err().contains("audience"));
        let other_acs = Expect { sp_entity_id: base.sp_entity_id, acs_url: "https://other/acs", ..other_aud };
        assert!(verify_response(&xml, &other_acs).unwrap_err().contains("Destination"));
        let other_idp = Expect { acs_url: base.acs_url, idp_entity_id: "https://evil", ..other_acs };
        assert!(verify_response(&xml, &other_idp).unwrap_err().contains("issuer"));
    }

    #[test]
    fn rejects_dtd() {
        assert!(parse("<!DOCTYPE x [<!ENTITY a \"b\">]><x>&a;</x>").is_err());
    }
}
