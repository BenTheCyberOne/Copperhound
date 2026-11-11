//! ldapdomaindump JSON records (`domain_users.json`, `domain_groups.json`,
//! `domain_computers.json`, `domain_policy.json`).
//!
//! Each record is `{"attributes": {"objectSid": [...], "memberOf": [DN...], ...},
//! "dn": "..."}`. Relationships are expressed as distinguished names, so DN
//! edges are emitted here and resolved globally after all files are parsed.

use crate::de::Many;
use crate::emit::{domain_from_dn, parent_dn, Emitter};
use crate::merge::cat;
use ch_model::{ek, flags, NodeKind};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Attrs {
    #[serde(rename = "objectSid")]
    pub object_sid: Many,
    #[serde(rename = "objectGUID")]
    pub object_guid: Many,
    #[serde(rename = "distinguishedName")]
    pub dn: Many,
    #[serde(rename = "sAMAccountName")]
    pub sam: Many,
    #[serde(rename = "dNSHostName")]
    pub dns_host: Many,
    #[serde(rename = "cn")]
    pub cn: Many,
    #[serde(rename = "objectClass")]
    pub object_class: Many,
    #[serde(rename = "memberOf")]
    pub member_of: Many,
    #[serde(rename = "member")]
    pub member: Many,
    #[serde(rename = "primaryGroupID")]
    pub primary_group_id: Many,
    #[serde(rename = "userAccountControl")]
    pub uac: Many,
    #[serde(rename = "adminCount")]
    pub admin_count: Many,
    #[serde(rename = "servicePrincipalName")]
    pub spn: Many,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Record {
    /// Kept raw: parsed into [`Attrs`] and, when properties are kept,
    /// normalised into the property column.
    pub attributes: Option<Box<RawValue>>,
    pub dn: Option<String>,
}

/// LDAP attributes → SharpHound-style properties: lowercase keys,
/// single-valued lists unwrapped, so queries like `n.description` work across
/// collectors.
fn normalize_props(raw: &str, name: Option<&str>) -> Option<Box<str>> {
    let map: serde_json::Map<String, Value> = serde_json::from_str(raw).ok()?;
    let mut out = serde_json::Map::with_capacity(map.len() + 1);
    for (k, v) in map {
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.pop().unwrap_or(Value::Null),
            v => v,
        };
        out.insert(k.to_ascii_lowercase(), v);
    }
    if let Some(n) = name {
        out.insert("name".into(), Value::String(n.to_ascii_uppercase()));
    }
    Some(Value::Object(out).to_string().into_boxed_str())
}

const UAC_ACCOUNTDISABLE: u64 = 0x2;
const UAC_TRUSTED_FOR_DELEGATION: u64 = 0x80000;
const UAC_DONT_REQ_PREAUTH: u64 = 0x40_0000;

fn kind_from_classes(classes: &[String]) -> Option<NodeKind> {
    let has = |c: &str| classes.iter().any(|x| x.eq_ignore_ascii_case(c));
    if has("computer") {
        Some(NodeKind::Computer)
    } else if has("group") {
        Some(NodeKind::Group)
    } else if has("user") {
        Some(NodeKind::User)
    } else if has("domainDNS") {
        Some(NodeKind::Domain)
    } else if has("organizationalUnit") {
        Some(NodeKind::Ou)
    } else if has("container") {
        Some(NodeKind::Container)
    } else {
        None
    }
}

/// `S-1-5-21-a-b-c-1104` → `S-1-5-21-a-b-c`.
fn domain_sid(sid: &str) -> Option<&str> {
    sid.starts_with("S-1-5-21-")
        .then(|| sid.rsplit_once('-').map(|(d, _)| d))
        .flatten()
}

pub fn extract(r: Record, file_kind: Option<NodeKind>, em: &mut Emitter) {
    let raw = r.attributes;
    let a: Attrs = raw
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .unwrap_or_default();
    if a.object_class
        .0
        .iter()
        .any(|c| c.eq_ignore_ascii_case("trustedDomain"))
    {
        return; // trust objects lack the target SID; SharpHound data covers trusts
    }
    let dn =
        a.dn.first()
            .map(str::to_string)
            .or(r.dn)
            .unwrap_or_default();
    let Some(oid) = a
        .object_sid
        .first()
        .or(a.object_guid.first())
        .or((!dn.is_empty()).then_some(dn.as_str()))
    else {
        return;
    };
    let oid = oid.to_string();

    let kind = kind_from_classes(&a.object_class.0).or(file_kind);
    let domain = domain_from_dn(&dn);
    let name = match kind {
        Some(NodeKind::Computer) => a.dns_host.first().map(str::to_string).or_else(|| {
            let sam = a.sam.first()?.trim_end_matches('$');
            Some(match &domain {
                Some(d) => format!("{sam}.{d}"),
                None => sam.to_string(),
            })
        }),
        Some(NodeKind::Domain) => domain.clone(),
        _ => a.sam.first().or(a.cn.first()).map(|s| match &domain {
            Some(d) => format!("{s}@{d}"),
            None => s.to_string(),
        }),
    };

    let uac = a.uac.first_u64().unwrap_or(0);
    let mut fl = 0;
    if kind != Some(NodeKind::Group) && uac & UAC_ACCOUNTDISABLE == 0 {
        fl |= flags::ENABLED;
    }
    if uac & UAC_TRUSTED_FOR_DELEGATION != 0 {
        fl |= flags::UNCONSTRAINED_DELEGATION;
    }
    if uac & UAC_DONT_REQ_PREAUTH != 0 {
        fl |= flags::DONT_REQ_PREAUTH;
    }
    if a.admin_count.first_u64().unwrap_or(0) != 0 {
        fl |= flags::ADMINCOUNT;
    }
    if !a.spn.0.is_empty() {
        fl |= flags::HAS_SPN;
    }

    let props = if em.keep_props() {
        raw.as_deref().and_then(|r| normalize_props(r.get(), name.as_deref()))
    } else {
        None
    };
    let Some(me) = em.own(&oid, kind, name.as_deref(), fl, props) else {
        return;
    };
    if let Some(d) = &domain {
        em.note_domain(d);
    }
    // Edge ownership (see `crate::merge`): LDAP omits empty attributes, so
    // only attributes present in the record are claimed.
    if !dn.is_empty() {
        em.dn_alias(&dn, me);
        if let Some(parent) = parent_dn(&dn) {
            em.scope(me, cat::CONTAINED_BY, false);
            em.dn_edge(me, parent, ek::CONTAINS, false, None);
        }
    }
    em.scope(me, cat::MEMBER_OF, !a.member_of.0.is_empty());
    for g in &a.member_of.0 {
        em.dn_edge(me, g, ek::MEMBER_OF, true, Some(NodeKind::Group));
    }
    em.scope(me, cat::MEMBERS, !a.member.0.is_empty());
    for m in &a.member.0 {
        em.dn_edge(me, m, ek::MEMBER_OF, false, Some(NodeKind::Unknown));
    }
    if let (Some(rid), Some(dsid)) = (a.primary_group_id.first_u64(), domain_sid(&oid)) {
        if let Some(g) = em.hint(&format!("{dsid}-{rid}"), Some(NodeKind::Group)) {
            em.scope(me, cat::PRIMARY_GROUP, true);
            em.edge(me, g, ek::MEMBER_OF);
        }
    }
}
