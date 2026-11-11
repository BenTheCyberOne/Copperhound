//! Two-pass extraction of SharpHound-equivalent nodes and edges from raw
//! directory entries (see the module docs of [`super`]).
//!
//! Conventions follow SharpHound CE so graphs from LDIF / snapshots and from
//! SharpHound JSON line up: object ids are SIDs for security principals and
//! domains and uppercase objectGUIDs otherwise; SIDs outside the
//! `S-1-5-21-…` domain space are prefixed with the domain name
//! (`CORP.LOCAL-S-1-5-32-544`); names are `SAM@DOMAIN`, `HOST.DOMAIN`, …;
//! membership comes from the group's `member` attribute plus the primary
//! group; containment from the parent DN.

use super::{cert, sd, Entry, Input, Need, Stats, A, NEED_ALL};
use crate::merge::cat;
use crate::emit::{domain_from_dn, normalize_dn, parent_dn, upper, Emitted, Emitter, Shared};
use ahash::{AHashMap, AHashSet, RandomState};
use ch_model::{ek, flags, NodeKind};
use rayon::prelude::*;
use serde::Serialize;
use std::sync::OnceLock;
use std::time::Instant;

/// SharpHound-style property object written straight into one buffer (no
/// intermediate `serde_json::Map`: one allocation per object). Keys are
/// inserted once each.
struct Props(Option<Vec<u8>>);

impl Props {
    fn new(keep: bool) -> Self {
        Props(keep.then(|| Vec::with_capacity(512)))
    }
    fn put(&mut self, k: &str, v: impl Serialize) {
        let Some(b) = &mut self.0 else { return };
        b.push(if b.is_empty() { b'{' } else { b',' });
        let _ = serde_json::to_writer(&mut *b, k);
        b.push(b':');
        let _ = serde_json::to_writer(&mut *b, &v);
    }
    fn finish(self) -> Option<Box<str>> {
        let mut b = self.0?;
        if b.is_empty() {
            b.push(b'{');
        }
        b.push(b'}');
        // serde_json only writes valid UTF-8.
        String::from_utf8(b).ok().map(String::into_boxed_str)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Node(NodeKind),
    Fsp,
    Trust,
    CrossRef,
    AttrSchema,
    Skip,
}

fn hasher() -> &'static RandomState {
    static H: OnceLock<RandomState> = OnceLock::new();
    H.get_or_init(|| RandomState::with_seeds(0x5eed_0001, 0x5eed_0002, 0x5eed_0003, 0x5eed_0004))
}
/// 64-bit hash of a normalised DN (or any other index key).
fn key(s: &str) -> u64 {
    hasher().hash_one(s)
}
fn host_key(h: &str) -> u64 {
    key(&format!("host:{}", h.to_ascii_uppercase()))
}

/// Domain part of a normalised DN: `CN=X,OU=Y,DC=A,DC=B` → `DC=A,DC=B`.
fn dc_suffix(ndn: &str) -> &str {
    if ndn.starts_with("DC=") {
        return ndn;
    }
    ndn.find(",DC=").map_or("", |i| &ndn[i + 1..])
}

/// `CN=CONFIGURATION,DC=…` suffix of a normalised DN in the Configuration NC.
fn config_root(ndn: &str) -> Option<&str> {
    let i = ndn.find("CN=CONFIGURATION,DC=")?;
    (i == 0 || ndn.as_bytes()[i - 1] == b',').then(|| &ndn[i..])
}

/// Value of the first RDN (`CN=Smith\, Bob,OU=…` → `Smith, Bob`).
fn rdn_value(dn: &str) -> &str {
    let first = parent_dn(dn).map_or(dn, |p| {
        let cut = dn.len() - p.len();
        dn[..cut].trim_end_matches([',', ' '])
    });
    first.split_once('=').map_or(first, |(_, v)| v)
}

fn classify(e: &Entry, ndn: &str) -> Class {
    use NodeKind as K;
    let has = |c: &str| e.has_class(c);
    let node = Class::Node;
    if has("msDS-GroupManagedServiceAccount") || has("msDS-ManagedServiceAccount") {
        return node(K::User);
    }
    if has("computer") {
        node(K::Computer)
    } else if has("group") {
        node(K::Group)
    } else if has("user") || has("inetOrgPerson") {
        node(K::User)
    } else if has("domainDNS") {
        // Application partitions (DomainDnsZones, …) are domainDNS without a SID.
        if e.has(A::ObjectSid) {
            node(K::Domain)
        } else {
            Class::Skip
        }
    } else if has("groupPolicyContainer") {
        node(K::Gpo)
    } else if has("organizationalUnit") {
        node(K::Ou)
    } else if has("pKICertificateTemplate") {
        node(K::CertTemplate)
    } else if has("pKIEnrollmentService") {
        node(K::EnterpriseCa)
    } else if has("certificationAuthority") {
        let parent = parent_dn(ndn).unwrap_or("");
        if ndn.starts_with("CN=NTAUTHCERTIFICATES,CN=PUBLIC KEY SERVICES,") {
            node(K::NtAuthStore)
        } else if parent.starts_with("CN=CERTIFICATION AUTHORITIES,CN=PUBLIC KEY SERVICES,") {
            node(K::RootCa)
        } else if parent.starts_with("CN=AIA,CN=PUBLIC KEY SERVICES,") {
            node(K::AiaCa)
        } else {
            Class::Skip
        }
    } else if has("msPKI-Enterprise-Oid") {
        // Only issuance policies (flags = 2), as SharpHound collects.
        if e.int(A::Flags) == Some(2) {
            node(K::IssuancePolicy)
        } else {
            Class::Skip
        }
    } else if has("foreignSecurityPrincipal") {
        Class::Fsp
    } else if has("trustedDomain") {
        Class::Trust
    } else if has("crossRef") {
        Class::CrossRef
    } else if has("attributeSchema") {
        Class::AttrSchema
    } else if has("container") {
        // SharpHound `IsDistinguishedNameFiltered`.
        if ndn.contains("CN=PROGRAM DATA,DC=") || ndn.contains("CN=SYSTEM,DC=") {
            Class::Skip
        } else {
            node(K::Container)
        }
    } else {
        Class::Skip
    }
}

fn deleted(e: &Entry) -> bool {
    e.text(A::IsDeleted).is_some_and(|v| v.eq_ignore_ascii_case("TRUE"))
}

fn uses_sid(k: NodeKind) -> bool {
    matches!(k, NodeKind::User | NodeKind::Computer | NodeKind::Group | NodeKind::Domain)
}

/// SharpHound identifier for a SID seen in `domain`.
fn prefixed(sid: String, domain: Option<&str>) -> String {
    match domain {
        Some(d) if !sid.starts_with("S-1-5-21-") && !d.is_empty() => format!("{d}-{sid}"),
        _ => sid,
    }
}

fn object_oid(e: &Entry, sid_based: bool, domain: Option<&str>) -> Option<String> {
    let guid = || e.first(A::ObjectGuid).and_then(sd::guid_value);
    if sid_based {
        e.first(A::ObjectSid).and_then(sd::sid_value).map(|s| prefixed(s, domain)).or_else(guid)
    } else {
        guid()
    }
}

fn fsp_oid(e: &Entry, domain: Option<&str>) -> Option<String> {
    let sid = e.first(A::ObjectSid).and_then(sd::sid_value).or_else(|| {
        let cn = rdn_value(&e.dn);
        cn.to_ascii_uppercase().starts_with("S-1-").then(|| cn.to_ascii_uppercase())
    })?;
    Some(prefixed(sid, domain))
}

const LAPS_ATTRS: &[&str] = &["ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"];

// ------------------------------------------------------------------ pass 1

#[derive(Default)]
struct IndexPart {
    dns: Vec<(u64, u32)>,
    hosts: Vec<(u64, u32)>,
    /// Domain naming context (normalised DN) → domain SID.
    domains: Vec<(String, String)>,
    /// `key(config root | template CN)` → template node.
    templates: Vec<(u64, u32)>,
    laps: Vec<sd::Guid>,
    /// CA certificates: subject → (thumbprint, issuer).
    certs: Vec<(Vec<u8>, String, Vec<u8>)>,
    /// Configuration NC → domain NC (crossRef objects), with the NetBIOS name.
    xrefs: Vec<(String, String, String)>,
}

const INDEX_NEED: &[A] = &[
    A::ObjectClass,
    A::ObjectSid,
    A::ObjectGuid,
    A::DnsHostName,
    A::SamAccountName,
    A::Cn,
    A::Name,
    A::CaCertificate,
    A::LdapDisplayName,
    A::SchemaIdGuid,
    A::NcName,
    A::NetbiosName,
    A::IsDeleted,
    A::Flags,
];

fn intern(sh: &Shared, oid: &str) -> u32 {
    sh.interner.intern(&upper(oid.trim()))
}

fn index_chunk(input: &Input, chunk: usize, sh: &Shared) -> IndexPart {
    let need: Need = INDEX_NEED.iter().fold(0, |m, a| m | a.bit());
    let mut p = IndexPart::default();
    input.read(chunk, need, &mut |r| {
        let Ok(e) = r else { return };
        if deleted(&e) {
            return;
        }
        let ndn = normalize_dn(&e.dn);
        let domain = domain_from_dn(&e.dn);
        match classify(&e, &ndn) {
            Class::Node(k) => {
                let Some(oid) = object_oid(&e, uses_sid(k), domain.as_deref()) else { return };
                let id = intern(sh, &oid);
                p.dns.push((key(&ndn), id));
                match k {
                    NodeKind::Computer => {
                        if let Some(h) = e.text(A::DnsHostName) {
                            p.hosts.push((host_key(h), id));
                        }
                        if let Some(sam) = e.text(A::SamAccountName) {
                            let short = sam.trim_end_matches('$');
                            p.hosts.push((host_key(short), id));
                            if let Some(d) = &domain {
                                p.hosts.push((host_key(&format!("{short}.{d}")), id));
                            }
                        }
                    }
                    NodeKind::Domain => p.domains.push((ndn.clone(), upper(&oid).into_owned())),
                    NodeKind::CertTemplate => {
                        if let (Some(root), Some(cn)) = (config_root(&ndn), e.text(A::Cn).or(e.text(A::Name))) {
                            p.templates.push((key(&format!("{root}|{}", cn.to_ascii_uppercase())), id));
                        }
                    }
                    _ => {}
                }
                if matches!(k, NodeKind::RootCa | NodeKind::AiaCa | NodeKind::EnterpriseCa | NodeKind::NtAuthStore) {
                    for der in e.all(A::CaCertificate) {
                        if let Some((iss, sub)) = cert::issuer_subject(der) {
                            p.certs.push((sub.to_vec(), cert::thumbprint(der), iss.to_vec()));
                        }
                    }
                }
            }
            Class::Fsp => {
                if let Some(oid) = fsp_oid(&e, domain.as_deref()) {
                    let id = intern(sh, &oid);
                    p.dns.push((key(&ndn), id));
                }
            }
            Class::AttrSchema => {
                let is_laps =
                    e.text(A::LdapDisplayName).is_some_and(|n| LAPS_ATTRS.iter().any(|l| l.eq_ignore_ascii_case(n)));
                if let Some(g) = e.first(A::SchemaIdGuid).filter(|_| is_laps).and_then(|g| <sd::Guid>::try_from(g).ok()) {
                    p.laps.push(g);
                }
            }
            Class::CrossRef => {
                if let (Some(root), Some(nc), Some(nb)) = (config_root(&ndn), e.text(A::NcName), e.text(A::NetbiosName)) {
                    p.xrefs.push((root.to_string(), normalize_dn(nc), nb.to_ascii_uppercase()));
                }
            }
            Class::Trust | Class::Skip => {}
        }
    });
    p
}

/// Global lookup tables built from pass 1.
struct Ctx {
    dn: AHashMap<u64, u32>,
    hosts: AHashMap<u64, u32>,
    domains: AHashMap<String, String>,
    templates: AHashMap<u64, u32>,
    laps: Vec<sd::Guid>,
    certs: AHashMap<Vec<u8>, (String, Vec<u8>)>,
    /// Configuration NC → SIDs of the forest's domains present in the input.
    forest: AHashMap<String, Vec<String>>,
    /// Domain NC (normalised DN) → NetBIOS name (crossRef `nETBIOSName`).
    netbios: AHashMap<String, String>,
}

impl Ctx {
    fn build(parts: Vec<IndexPart>) -> Ctx {
        let n: usize = parts.iter().map(|p| p.dns.len()).sum();
        let mut c = Ctx {
            dn: AHashMap::with_capacity(n),
            hosts: AHashMap::new(),
            domains: AHashMap::new(),
            templates: AHashMap::new(),
            laps: LAPS_LEGACY_DEFAULT.to_vec(),
            certs: AHashMap::new(),
            forest: AHashMap::new(),
            netbios: AHashMap::new(),
        };
        let mut xrefs = Vec::new();
        for p in parts {
            c.dn.extend(p.dns);
            for (h, id) in p.hosts {
                c.hosts.entry(h).or_insert(id);
            }
            c.domains.extend(p.domains);
            c.templates.extend(p.templates);
            c.laps.extend(p.laps);
            for (sub, thumb, iss) in p.certs {
                c.certs.insert(sub, (thumb, iss));
            }
            xrefs.extend(p.xrefs);
        }
        c.laps.sort_unstable();
        c.laps.dedup();
        for (root, nc, nb) in xrefs {
            c.netbios.insert(nc.clone(), nb);
            if let Some(sid) = c.domains.get(&nc) {
                let v = c.forest.entry(root).or_default();
                if !v.contains(sid) {
                    v.push(sid.clone());
                }
            }
        }
        c
    }

    fn resolve(&self, dn: &str) -> Option<u32> {
        self.dn.get(&key(&normalize_dn(dn))).copied()
    }

    /// Domains a forest-wide (Configuration NC) object applies to.
    fn forest_domains(&self, root: &str) -> Vec<String> {
        match self.forest.get(root) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => self.domains.get(dc_suffix(root)).cloned().into_iter().collect(),
        }
    }
}

/// No legacy-LAPS GUID is fixed (the schema extension generates one per
/// forest); it is read from the Schema NC when the dump includes it.
const LAPS_LEGACY_DEFAULT: &[sd::Guid] = &[];

// ------------------------------------------------------------------ pass 2

struct X<'c, 'e, 's> {
    ctx: &'c Ctx,
    em: &'e mut Emitter<'s>,
    named: AHashSet<u32>,
    rights: Vec<&'static str>,
    resolved: u64,
    unresolved: u64,
}

fn ft_to_unix(v: Option<i64>) -> Option<i64> {
    v.map(|ft| match ft {
        0 => 0,
        i64::MAX => -1,
        ft if ft < 0 => -1,
        ft => ft / 10_000_000 - 11_644_473_600,
    })
}

/// GeneralizedTime `YYYYMMDDHHMMSS[.f]Z` → unix seconds.
fn gen_time(s: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(4..6)?, n(6..8)?, n(8..10)?, n(10..12)?, n(12..14)?);
    // days_from_civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// `pKIExpirationPeriod` / `pKIOverlapPeriod` → SharpHound text ("1 year").
fn pki_period(b: &[u8]) -> Option<String> {
    let v = i64::from_le_bytes(b.try_into().ok()?);
    let secs = v.checked_neg()? / 10_000_000;
    for (unit, name) in [(31_536_000, "year"), (2_592_000, "month"), (604_800, "week"), (86_400, "day"), (3600, "hour")] {
        if secs >= unit && secs % unit == 0 {
            let n = secs / unit;
            return Some(format!("{n} {name}{}", if n > 1 { "s" } else { "" }));
        }
    }
    None
}

fn functional_level(v: i64) -> &'static str {
    match v {
        0 => "2000 Mixed/Native",
        1 => "2003 Interim",
        2 => "2003",
        3 => "2008",
        4 => "2008 R2",
        5 => "2012",
        6 => "2012 R2",
        7 => "2016",
        10 => "2025",
        _ => "Unknown",
    }
}

/// `gPLink` → `(GPO DN, status)`; status 1 / 3 = link disabled.
fn gplinks(s: &str) -> Vec<(&str, u32)> {
    s.split('[')
        .filter_map(|part| {
            let part = part.trim().trim_end_matches(']');
            let (dn, st) = part.rsplit_once(';')?;
            let dn = dn.get(7..).filter(|_| dn.len() > 7 && dn[..7].eq_ignore_ascii_case("LDAP://"))?;
            Some((dn, st.trim().parse().unwrap_or(0)))
        })
        .collect()
}

/// Host part of an SPN (`cifs/fs01.corp.local:445` → `fs01.corp.local`).
fn spn_host(spn: &str) -> Option<&str> {
    let rest = spn.split_once('/')?.1;
    let h = rest.split(['/', ':']).next()?;
    (!h.is_empty()).then_some(h)
}

const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const OID_PKINIT: &str = "1.3.6.1.5.2.3.4";
const OID_SMARTCARD: &str = "1.3.6.1.4.1.311.20.2.2";
const OID_ANY: &str = "2.5.29.37.0";

/// SharpHound `ReadCertTemplateProperties` derived booleans and lists.
fn template_props(e: &Entry, p: &mut Props) {
    let strs = |a: A| -> Vec<String> { e.texts(a).map(str::to_string).collect() };
    let schema = e.int(A::SchemaVersion);
    if let Some(v) = schema {
        p.put("schemaversion", v);
    }
    if let Some(v) = e.text(A::TemplateOid) {
        p.put("oid", v);
    }
    if let Some(v) = e.text(A::DisplayName) {
        p.put("displayname", v);
    }
    for (a, k) in [(A::ExpirationPeriod, "validityperiod"), (A::OverlapPeriod, "renewalperiod")] {
        if let Some(v) = e.first(a).and_then(pki_period) {
            p.put(k, v);
        }
    }
    if let Some(ef) = e.int(A::EnrollmentFlag).map(|v| v as u32) {
        p.put("requiresmanagerapproval", ef & 0x2 != 0);
        p.put("nosecurityextension", ef & 0x80000 != 0);
    }
    if let Some(nf) = e.int(A::NameFlag).map(|v| v as u32) {
        for (bit, k) in [
            (0x1, "enrolleesuppliessubject"),
            (0x0200_0000, "subjectaltrequireupn"),
            (0x0800_0000, "subjectaltrequiredns"),
            (0x0040_0000, "subjectaltrequiredomaindns"),
            (0x0400_0000, "subjectaltrequireemail"),
            (0x0080_0000, "subjectaltrequirespn"),
            (0x2000_0000, "subjectrequireemail"),
        ] {
            p.put(k, nf & bit != 0);
        }
    }
    let ekus = strs(A::Eku);
    let app = strs(A::AppPolicy);
    p.put("ekus", &ekus);
    p.put("certificateapplicationpolicy", &app);
    p.put("certificatepolicy", strs(A::CertPolicy));
    if let Some(v) = e.int(A::RaSignature) {
        p.put("authorizedsignatures", v);
    }
    // Schema v3+ stores `Name`Type`Value` triples; v1/v2 plain OIDs.
    let raw = strs(A::RaAppPolicies);
    let app_pols: Vec<String> = if raw.iter().any(|v| v.contains('`')) {
        raw.iter()
            .flat_map(|v| {
                let parts: Vec<&str> = v.split('`').collect();
                parts
                    .chunks(3)
                    .filter(|t| t.len() == 3 && t[0].eq_ignore_ascii_case("msPKI-RA-Application-Policies"))
                    .map(|t| t[2].to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    } else {
        raw
    };
    p.put("applicationpolicies", app_pols);
    p.put("issuancepolicies", strs(A::RaPolicies));
    let effective = if schema.unwrap_or(0) == 1 && !ekus.is_empty() { ekus } else { app };
    let any = |oids: &[&str]| effective.is_empty() || effective.iter().any(|e| oids.contains(&e.as_str()));
    p.put("authenticationenabled", any(&[OID_CLIENT_AUTH, OID_PKINIT, OID_SMARTCARD, OID_ANY]));
    p.put("schannelauthenticationenabled", any(&[OID_CLIENT_AUTH, OID_ANY]));
    p.put("effectiveekus", effective);
}

impl X<'_, '_, '_> {
    /// Node id of an ACE / attribute principal SID, or `None` if filtered.
    fn principal(&mut self, sid: &str, dom: &str) -> Option<u32> {
        if sd::sid_filtered(sid) {
            return None;
        }
        if sid.starts_with("S-1-5-21-") || dom.is_empty() {
            return self.em.id(sid);
        }
        let oid = format!("{dom}-{sid}");
        let id = self.em.id(&oid)?;
        if self.named.insert(id) {
            if let Some((name, kind)) = sd::well_known(sid) {
                self.em.hint_named(&oid, kind, Some(&format!("{name}@{dom}")));
            }
        }
        Some(id)
    }

    fn dn_ref(&mut self, dn: &str) -> Option<u32> {
        let r = self.ctx.resolve(dn);
        if r.is_some() {
            self.resolved += 1;
        } else {
            self.unresolved += 1;
        }
        r
    }

    /// Principals granted by the allowed ACEs of an attribute-held SD
    /// (RBCD, gMSA password readers).
    fn sd_principals(&mut self, v: &[u8], dom: &str) -> Vec<u32> {
        let Some(s) = sd::parse(v) else { return Vec::new() };
        let sids: Vec<String> = s.dacl.iter().filter_map(|a| sd::sid_string(a.sid)).collect();
        sids.iter().filter_map(|sid| self.principal(sid, dom)).collect()
    }

    fn acl(&mut self, s: &sd::Sd, me: u32, t: &sd::Target, dom: &str) {
        if let Some(o) = s.owner.and_then(sd::sid_string) {
            if let Some(p) = self.principal(&o, dom) {
                let k = self.em.kind_id("Owns");
                self.em.edge(p, me, k);
            }
        }
        let mut rights = std::mem::take(&mut self.rights);
        for ace in &s.dacl {
            rights.clear();
            sd::ace_rights(ace, t, &mut rights);
            if rights.is_empty() {
                continue;
            }
            let Some(p) = sd::sid_string(ace.sid).and_then(|sid| self.principal(&sid, dom)) else { continue };
            for r in &rights {
                let k = self.em.kind_id(r);
                self.em.edge(p, me, k);
            }
        }
        self.rights = rights;
    }

    fn chain(&self, der: &[u8]) -> Vec<String> {
        let mut out = vec![cert::thumbprint(der)];
        let Some((iss, sub)) = cert::issuer_subject(der) else { return out };
        let (mut iss, mut sub) = (iss.to_vec(), sub.to_vec());
        for _ in 0..8 {
            if iss == sub {
                break;
            }
            let Some((t, next)) = self.ctx.certs.get(&iss) else { break };
            if out.contains(t) {
                break;
            }
            out.push(t.clone());
            sub = std::mem::replace(&mut iss, next.clone());
        }
        out
    }

    fn trust(&mut self, e: &Entry, ndn: &str) {
        let Some(dsid) = self.ctx.domains.get(dc_suffix(ndn)) else { return };
        let Some(other_sid) = e.first(A::SecurityIdentifier).and_then(sd::sid_value) else { return };
        let Some(me) = self.em.hint(dsid, Some(NodeKind::Domain)) else { return };
        let name = e.text(A::TrustPartner);
        let Some(other) = self.em.hint_named(&other_sid, NodeKind::Domain, name) else { return };
        // The trustedDomain objects of a domain together are its trust list
        // (SharpHound's `Trusts` on the domain record).
        self.em.scope(me, cat::TRUSTS, true);
        // Same semantics as SharpHound `Trusts` (see sharphound.rs).
        let dir = e.int(A::TrustDirection).unwrap_or(0);
        // trustAttributes bits (MS-ADTS 6.1.6.7.9): 0x4 QUARANTINED_DOMAIN
        // (SID filtering on an external trust), 0x8 FOREST_TRANSITIVE,
        // 0x20 WITHIN_FOREST, 0x40 TREAT_AS_EXTERNAL (forest trust relaxed to
        // external SID filtering, which admits SID history), 0x800
        // CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION. Without the attribute only
        // TrustedBy is emitted, like SharpHound records without TrustType.
        let attrs = e.int(A::TrustAttributes).map(|a| a as u32);
        let kinds = attrs.map(|a| {
            let forest = a & 0x8 != 0;
            let spoofable = if forest { a & 0x40 != 0 } else { a & 0x4 == 0 };
            (a & 0x20 != 0, spoofable, a & 0x800 != 0)
        });
        if dir == 2 || dir == 3 {
            self.em.edge(other, me, ek::TRUSTED_BY);
            if let Some((sf, sp, tgt)) = kinds {
                crate::sharphound::emit_trust(self.em, me, other, sf, sp, tgt);
            }
        }
        if dir == 1 || dir == 3 {
            self.em.edge(me, other, ek::TRUSTED_BY);
            if let Some((sf, sp, tgt)) = kinds {
                crate::sharphound::emit_trust(self.em, other, me, sf, sp, tgt);
            }
        }
    }

    /// Emit `member` edges of group `me`. Returns `false` if a member could
    /// not be resolved (the entry then cannot claim the membership list).
    fn members(&mut self, e: &Entry, me: u32, dom: &str) -> bool {
        let mut complete = true;
        let members: Vec<&str> = e.texts(A::Member).collect();
        for m in members {
            let id = match self.dn_ref(m) {
                Some(id) => Some(id),
                None => {
                    // Foreign principal not present as an object: its SID is the CN.
                    let cn = rdn_value(m).to_ascii_uppercase();
                    normalize_dn(m)
                        .contains(",CN=FOREIGNSECURITYPRINCIPALS,")
                        .then_some(cn)
                        .filter(|c| c.starts_with("S-1-"))
                        .and_then(|sid| self.principal(&sid, dom))
                }
            };
            match id {
                Some(id) => self.em.edge(id, me, ek::MEMBER_OF),
                None => complete = false,
            }
        }
        complete
    }

    /// A continuation entry of a ranged `member` read (`member;range=1500-*`
    /// and no first range): members of the group at this DN. It adds to the
    /// group's membership and never replaces the group's own record.
    fn member_supplement(&mut self, e: &Entry) {
        // Unresolved (group not in the input) counts as an unresolved reference.
        let Some(g) = self.dn_ref(&e.dn) else { return };
        let dom = domain_from_dn(&e.dn).unwrap_or_default();
        self.em.scope(g, cat::MEMBERS, false);
        self.members(e, g, &dom);
        self.em.unscoped();
    }

    fn entry(&mut self, e: &Entry) {
        use NodeKind as K;
        self.em.begin();
        if deleted(e) {
            return;
        }
        if let Some(t) = e.text(A::WhenChanged).and_then(gen_time) {
            self.em.note_changed(t);
        }
        if e.member_tail && !e.member_head {
            return self.member_supplement(e);
        }
        let ndn = normalize_dn(&e.dn);
        let domain = domain_from_dn(&e.dn);
        let kind = match classify(e, &ndn) {
            Class::Node(k) => k,
            Class::Trust => return self.trust(e, &ndn),
            Class::Fsp => {
                // Well-known principals (Authenticated Users, …) get their
                // SharpHound node; foreign accounts stay references only.
                if let Some(sid) = e.first(A::ObjectSid).and_then(sd::sid_value) {
                    if sd::well_known(&sid).is_some() {
                        self.principal(&sid, domain.as_deref().unwrap_or(""));
                    }
                }
                return;
            }
            _ => return,
        };
        if let Some(d) = &domain {
            self.em.note_domain(d);
        }
        let dom = domain.clone().unwrap_or_default();
        let dsid = self.ctx.domains.get(dc_suffix(&ndn)).cloned();
        let Some(oid) = object_oid(e, uses_sid(kind), domain.as_deref()) else {
            self.em.error(|| format!("{}: no objectSid / objectGUID", e.dn));
            return;
        };
        let uac = e.int(A::Uac).unwrap_or(0) as u64 & 0xFFFF_FFFF;
        let sam = e.text(A::SamAccountName);
        let rdn = e.text(A::Name).or(e.text(A::Cn)).unwrap_or_else(|| rdn_value(&e.dn));
        let at = |n: &str| if dom.is_empty() { n.to_string() } else { format!("{n}@{dom}") };
        let name = match kind {
            K::Computer => e.text(A::DnsHostName).map(str::to_string).unwrap_or_else(|| {
                let short = sam.unwrap_or(rdn).trim_end_matches('$');
                if dom.is_empty() { short.to_string() } else { format!("{short}.{dom}") }
            }),
            K::User | K::Group => at(sam.unwrap_or(rdn)),
            K::Domain => dom.clone(),
            K::Gpo | K::IssuancePolicy => at(e.text(A::DisplayName).unwrap_or(rdn)),
            _ => at(rdn),
        }
        .to_ascii_uppercase();

        let mut p = Props::new(self.em.keep_props());
        p.put("name", &name);
        p.put("domain", &dom);
        if let Some(s) = &dsid {
            p.put("domainsid", s);
        }
        p.put("distinguishedname", &ndn);
        p.put("objectid", upper(&oid));
        if let Some(d) = e.text(A::Description) {
            p.put("description", d);
        }
        if let Some(t) = e.text(A::WhenCreated).and_then(gen_time) {
            p.put("whencreated", t);
        }
        let mut fl = 0u32;
        let admincount = e.int(A::AdminCount).unwrap_or(0) != 0;
        if admincount {
            fl |= flags::ADMINCOUNT;
        }
        let sdp = e.first(A::Sd).and_then(sd::parse);
        if let Some(s) = &sdp {
            p.put("isaclprotected", s.protected());
        }
        let spns: Vec<&str> = e.texts(A::Spn).collect();
        let sid_history: Vec<String> = e.all(A::SidHistory).filter_map(sd::sid_value).collect();
        let delegate_to: Vec<&str> = e.texts(A::AllowedToDelegateTo).collect();
        let has_laps = e.has(A::LapsLegacyExpiry) || e.has(A::LapsExpiry);

        if matches!(kind, K::User | K::Computer) {
            let enabled = uac & 0x2 == 0;
            if enabled {
                fl |= flags::ENABLED;
            }
            if uac & 0x80000 != 0 {
                fl |= flags::UNCONSTRAINED_DELEGATION;
            }
            p.put("samaccountname", sam);
            p.put("enabled", enabled);
            p.put("unconstraineddelegation", uac & 0x80000 != 0);
            p.put("trustedtoauth", uac & 0x0100_0000 != 0);
            p.put("admincount", admincount);
            for (a, k) in [(A::LastLogon, "lastlogon"), (A::LastLogonTimestamp, "lastlogontimestamp"), (A::PwdLastSet, "pwdlastset")] {
                if let Some(v) = ft_to_unix(e.int(a)) {
                    p.put(k, v);
                }
            }
            p.put("serviceprincipalnames", &spns);
            p.put("sidhistory", &sid_history);
            p.put("allowedtodelegate", &delegate_to);
        }
        match kind {
            K::User => {
                if uac & 0x40_0000 != 0 {
                    fl |= flags::DONT_REQ_PREAUTH;
                }
                if !spns.is_empty() {
                    fl |= flags::HAS_SPN;
                }
                p.put("hasspn", !spns.is_empty());
                p.put("dontreqpreauth", uac & 0x40_0000 != 0);
                p.put("passwordnotreqd", uac & 0x20 != 0);
                p.put("pwdneverexpires", uac & 0x10000 != 0);
                p.put("sensitive", uac & 0x10_0000 != 0);
                p.put("gmsa", e.has_class("msDS-GroupManagedServiceAccount"));
                p.put("msa", e.has_class("msDS-ManagedServiceAccount"));
                for (a, k) in [
                    (A::DisplayName, "displayname"),
                    (A::Mail, "email"),
                    (A::Title, "title"),
                    (A::HomeDirectory, "homedirectory"),
                    (A::ScriptPath, "logonscript"),
                    (A::UserPassword, "userpassword"),
                    (A::UnixUserPassword, "unixpassword"),
                    (A::UnicodePwd, "unicodepassword"),
                    (A::SfuPassword, "sfupassword"),
                ] {
                    if let Some(v) = e.first(a) {
                        p.put(k, String::from_utf8_lossy(v));
                    }
                }
            }
            K::Computer => {
                let os = match (e.text(A::OperatingSystem), e.text(A::OsServicePack)) {
                    (Some(o), Some(sp)) => Some(format!("{o} {sp}")),
                    (o, _) => o.map(str::to_string),
                };
                if let Some(os) = os {
                    p.put("operatingsystem", os);
                }
                p.put("haslaps", has_laps);
                p.put("isdc", uac & 0x2000 != 0);
            }
            K::Group => {
                p.put("samaccountname", sam);
                p.put("admincount", admincount);
            }
            K::Domain => {
                if let Some(v) = e.int(A::BehaviorVersion) {
                    p.put("functionallevel", functional_level(v));
                }
                if let Some(v) = e.int(A::MachineAccountQuota) {
                    p.put("machineaccountquota", v);
                }
                if let Some(nb) = self.ctx.netbios.get(&ndn) {
                    p.put("netbios", nb.as_str());
                }
            }
            K::Gpo => {
                if let Some(v) = e.text(A::GpcFileSysPath) {
                    p.put("gpcpath", v.to_ascii_uppercase());
                }
            }
            K::Ou => {
                p.put("blocksinheritance", e.int(A::GpOptions).unwrap_or(0) & 1 == 1);
            }
            K::CertTemplate => template_props(e, &mut p),
            K::EnterpriseCa | K::RootCa | K::AiaCa => {
                if let Some(der) = e.first(A::CaCertificate) {
                    let chain = self.chain(der);
                    p.put("certthumbprint", &chain[0]);
                    p.put("certname", &chain[0]);
                    p.put("certchain", chain);
                }
                p.put("hasbasicconstraints", false);
                p.put("basicconstraintpathlength", 0);
                if kind == K::EnterpriseCa {
                    p.put("caname", rdn);
                    if let Some(h) = e.text(A::DnsHostName) {
                        p.put("dnshostname", h);
                    }
                }
                if kind == K::AiaCa {
                    let pairs: Vec<String> = e.all(A::CrossCertificatePair).map(cert::thumbprint).collect();
                    p.put("hascrosscertificatepair", !pairs.is_empty());
                    p.put("crosscertificatepair", pairs);
                }
            }
            K::NtAuthStore => {
                let thumbs: Vec<String> = e.all(A::CaCertificate).map(cert::thumbprint).collect();
                p.put("certthumbprints", thumbs);
            }
            K::IssuancePolicy => {
                if let Some(v) = e.text(A::DisplayName) {
                    p.put("displayname", v);
                }
                if let Some(v) = e.text(A::TemplateOid) {
                    p.put("certtemplateoid", v);
                }
            }
            _ => {}
        }

        // Published templates are resolved before the node is emitted so
        // unresolved names land in the properties.
        let mut published = Vec::new();
        let mut published_complete = true;
        if kind == K::EnterpriseCa {
            let root = config_root(&ndn).unwrap_or("");
            let mut unresolved = Vec::new();
            for cn in e.texts(A::CertificateTemplates) {
                match self.ctx.templates.get(&key(&format!("{root}|{}", cn.to_ascii_uppercase()))) {
                    Some(&t) => published.push(t),
                    None => unresolved.push(cn.to_string()),
                }
            }
            published_complete = unresolved.is_empty();
            p.put("unresolvedpublishedtemplates", unresolved);
        }

        let props = p.finish();
        let Some(me) = self.em.own(&oid, Some(kind), Some(&name), fl, props) else { return };

        // Edge ownership (see `crate::merge`): this entry claims a category
        // only when it holds the attribute and every reference in it was
        // resolved — LDAP omits empty attributes and a dump may lack the
        // referenced objects, so absence never supersedes older data.

        // ---- containment
        if kind != K::Domain {
            if let Some(parent) = parent_dn(&ndn).and_then(|pd| self.ctx.resolve(pd)) {
                self.em.scope(me, cat::CONTAINED_BY, true);
                self.em.edge(parent, me, ek::CONTAINS);
            }
        }

        // ---- ACL
        if let Some(s) = &sdp {
            self.em.scope(me, cat::ACES, true);
            let class = e.texts(A::ObjectClass).last().and_then(sd::class_guid);
            let t = sd::Target { kind, class, has_laps, laps: &self.ctx.laps };
            self.acl(s, me, &t, &dom);
        }

        // ---- membership
        if kind == K::Group {
            self.em.scope(me, cat::MEMBERS, false);
            // A first range (`member;range=0-1499`) claims too: later ranges
            // arrive as supplements from a newer or equal collection.
            if self.members(e, me, &dom) && (e.member_head || !e.member_tail) && e.has(A::Member) {
                self.em.claim(me, cat::MEMBERS);
            }
        }
        if matches!(kind, K::User | K::Computer) {
            let own_sid = upper(&oid);
            if let (Some(rid), Some((dsid, _))) = (e.int(A::PrimaryGroupId), own_sid.rsplit_once('-')) {
                if own_sid.starts_with("S-1-5-21-") {
                    if let Some(g) = self.em.hint(&format!("{dsid}-{rid}"), Some(K::Group)) {
                        self.em.scope(me, cat::PRIMARY_GROUP, true);
                        self.em.edge(me, g, ek::MEMBER_OF);
                    }
                }
            }
            // ---- delegation, RBCD, SID history, gMSA readers
            self.em.scope(me, cat::DELEGATE, false);
            let mut complete = true;
            for spn in &delegate_to {
                let Some(h) = spn_host(spn) else { continue };
                let short = h.split('.').next().unwrap_or(h);
                match self.ctx.hosts.get(&host_key(h)).or_else(|| self.ctx.hosts.get(&host_key(short))) {
                    Some(&c) => self.em.edge(me, c, ek::ALLOWED_TO_DELEGATE),
                    None => complete = false,
                }
            }
            if complete && !delegate_to.is_empty() {
                self.em.claim(me, cat::DELEGATE);
            }
            let vals: Vec<Vec<u8>> = e.all(A::AllowedToAct).map(<[u8]>::to_vec).collect();
            self.em.scope(me, cat::ALLOWED_TO_ACT, !vals.is_empty() && vals.iter().all(|v| sd::parse(v).is_some()));
            for v in vals {
                for pr in self.sd_principals(&v, &dom) {
                    self.em.edge(pr, me, ek::ALLOWED_TO_ACT);
                }
            }
            self.em.scope(me, cat::SID_HISTORY, !sid_history.is_empty());
            for sid in &sid_history {
                if let Some(x) = self.principal(sid, &dom) {
                    self.em.edge(me, x, ek::HAS_SID_HISTORY);
                }
            }
            let vals: Vec<Vec<u8>> = e.all(A::GmsaMembership).map(<[u8]>::to_vec).collect();
            self.em.scope(me, cat::GMSA, !vals.is_empty() && vals.iter().all(|v| sd::parse(v).is_some()));
            let k = self.em.kind_id("ReadGMSAPassword");
            for v in vals {
                for pr in self.sd_principals(&v, &dom) {
                    self.em.edge(pr, me, k);
                }
            }
        }

        // ---- GPO links
        if matches!(kind, K::Domain | K::Ou) {
            if let Some(gl) = e.text(A::GpLink) {
                self.em.scope(me, cat::GP_LINKS, false);
                let mut complete = true;
                for (gpo_dn, status) in gplinks(gl) {
                    if status == 1 || status == 3 {
                        continue;
                    }
                    match self.dn_ref(gpo_dn) {
                        Some(g) => self.em.edge(g, me, ek::GP_LINK),
                        None => complete = false,
                    }
                }
                if complete {
                    self.em.claim(me, cat::GP_LINKS);
                }
            }
        }

        // ---- ADCS structure
        let root = config_root(&ndn).unwrap_or("").to_string();
        match kind {
            K::EnterpriseCa => {
                let k = self.em.kind_id("PublishedTo");
                self.em.scope(me, cat::PUBLISHED_TEMPLATES, published_complete && e.has(A::CertificateTemplates));
                for t in published {
                    self.em.edge(t, me, k);
                }
                if let Some(h) = e.text(A::DnsHostName) {
                    if let Some(&c) = self.ctx.hosts.get(&host_key(h)) {
                        self.em.scope(me, cat::HOSTING, true);
                        let k = self.em.kind_id("HostsCAService");
                        self.em.edge(c, me, k);
                    }
                }
            }
            K::RootCa | K::NtAuthStore => {
                // Derived from the forest's domains present in this input:
                // not owned (never superseded).
                self.em.unscoped();
                let k = self.em.kind_id(if kind == K::RootCa { "RootCAFor" } else { "NTAuthStoreFor" });
                for d in self.ctx.forest_domains(&root) {
                    if let Some(d) = self.em.hint(&d, Some(K::Domain)) {
                        self.em.edge(me, d, k);
                    }
                }
            }
            K::IssuancePolicy => {
                if let Some(g) = e.text(A::OidToGroupLink).and_then(|dn| self.dn_ref(dn)) {
                    self.em.scope(me, cat::GROUP_LINK, true);
                    let k = self.em.kind_id("OIDGroupLink");
                    self.em.edge(me, g, k);
                }
            }
            _ => {}
        }
    }
}

fn extract_chunk(input: &Input, chunk: usize, sh: &Shared, ctx: &Ctx) -> (Emitted, u64, u64) {
    let mut em = Emitter::new(sh, None);
    em.out.source = input.source;
    let mut x = X { ctx, em: &mut em, named: AHashSet::new(), rights: Vec::new(), resolved: 0, unresolved: 0 };
    let mut records = 0u64;
    let display = &input.display;
    input.read(chunk, NEED_ALL, &mut |r| {
        records += 1;
        match r {
            Ok(e) => x.entry(&e),
            Err(err) => x.em.error(|| format!("{display}: {err}")),
        }
    });
    let (resolved, unresolved) = (x.resolved, x.unresolved);
    em.out.records = records;
    (em.finish(), resolved, unresolved)
}

pub(super) fn run(inputs: &[Input], sh: &Shared, progress: crate::Progress) -> (Vec<Emitted>, Stats) {
    let mut stats = Stats::default();
    let jobs: Vec<(usize, usize)> =
        inputs.iter().enumerate().flat_map(|(i, inp)| (0..inp.chunks()).map(move |c| (i, c))).collect();
    let total = jobs.len().max(1);
    let done = std::sync::atomic::AtomicUsize::new(0);
    let tick = |base: u8, span: usize| {
        let d = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if d * 10 / total != (d - 1) * 10 / total {
            progress(if base < 30 { "indexing" } else { "parsing" }, base + (span * d / total) as u8);
        }
    };

    progress("indexing", 16);
    let t = Instant::now();
    let parts: Vec<IndexPart> = jobs
        .par_iter()
        .map(|&(i, c)| {
            let p = index_chunk(&inputs[i], c, sh);
            tick(16, 14);
            p
        })
        .collect();
    let ctx = Ctx::build(parts);
    stats.index_secs = t.elapsed().as_secs_f64();

    done.store(0, std::sync::atomic::Ordering::Relaxed);
    progress("parsing", 30);
    let outs: Vec<(Emitted, u64, u64)> = jobs
        .par_iter()
        .map(|&(i, c)| {
            let o = extract_chunk(&inputs[i], c, sh, &ctx);
            tick(30, 20);
            o
        })
        .collect();
    let mut emitted = Vec::with_capacity(outs.len());
    for (o, r, u) in outs {
        stats.records += o.records;
        stats.refs_resolved += r;
        stats.refs_unresolved += u;
        emitted.push(o);
    }
    (emitted, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(dc_suffix("CN=A,OU=B,DC=CORP,DC=LOCAL"), "DC=CORP,DC=LOCAL");
        assert_eq!(dc_suffix("DC=CORP,DC=LOCAL"), "DC=CORP,DC=LOCAL");
        assert_eq!(
            config_root("CN=X,CN=CERTIFICATE TEMPLATES,CN=CONFIGURATION,DC=CORP,DC=LOCAL"),
            Some("CN=CONFIGURATION,DC=CORP,DC=LOCAL")
        );
        assert_eq!(rdn_value("CN=Smith\\, Bob,OU=Staff,DC=x"), "Smith\\, Bob");
        assert_eq!(gen_time("20240102030405.0Z"), Some(1_704_164_645));
        assert_eq!(gen_time("19700101000000.0Z"), Some(0));
        assert_eq!(ft_to_unix(Some(133_500_000_000_000_000)), Some(1_705_526_400));
        assert_eq!(pki_period(&(-315_360_000_000_000i64).to_le_bytes()).as_deref(), Some("1 year"));
        assert_eq!(pki_period(&(-36_288_000_000_000i64).to_le_bytes()).as_deref(), Some("6 weeks"));
        assert_eq!(spn_host("cifs/fs01.corp.local:445"), Some("fs01.corp.local"));
        assert_eq!(
            gplinks("[LDAP://cn={A},cn=policies,cn=system,DC=corp,DC=local;0][LDAP://CN={B},CN=Policies,CN=System,DC=corp,DC=local;1]"),
            vec![("cn={A},cn=policies,cn=system,DC=corp,DC=local", 0), ("CN={B},CN=Policies,CN=System,DC=corp,DC=local", 1)]
        );
    }
}
