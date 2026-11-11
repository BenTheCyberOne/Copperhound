//! SharpHound / bloodhound-python JSON records (collector formats v4–v6).

use crate::de::{lenient_bool, lenient_string, trust_direction, Ref, Results};
use crate::emit::Emitter;
use crate::merge::cat;
use ch_model::{ek, flags, NodeKind};
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Meta {
    #[serde(rename = "type")]
    pub ty: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Props {
    pub name: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub domain: Option<String>,
    #[serde(deserialize_with = "lenient_bool")]
    pub enabled: Option<bool>,
    #[serde(deserialize_with = "lenient_bool")]
    pub highvalue: Option<bool>,
    #[serde(deserialize_with = "lenient_bool")]
    pub admincount: Option<bool>,
    #[serde(deserialize_with = "lenient_bool")]
    pub unconstraineddelegation: Option<bool>,
    #[serde(deserialize_with = "lenient_bool")]
    pub dontreqpreauth: Option<bool>,
    #[serde(deserialize_with = "lenient_bool")]
    pub hasspn: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Ace {
    #[serde(rename = "PrincipalSID")]
    pub principal_sid: Option<String>,
    #[serde(rename = "PrincipalType")]
    pub principal_type: Option<String>,
    #[serde(rename = "RightName")]
    pub right_name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Session {
    #[serde(rename = "ComputerSID")]
    pub computer: Option<String>,
    #[serde(rename = "UserSID")]
    pub user: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct LocalGroup {
    #[serde(rename = "ObjectIdentifier")]
    pub oid: Option<String>,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Results")]
    pub results: Option<Vec<Ref>>,
    #[serde(rename = "Collected", deserialize_with = "lenient_bool")]
    pub collected: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Link {
    #[serde(rename = "GUID")]
    pub guid: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Trust {
    #[serde(rename = "TargetDomainSid")]
    pub target_sid: Option<String>,
    #[serde(rename = "TargetDomainName")]
    pub target_name: Option<String>,
    #[serde(rename = "TrustDirection", deserialize_with = "trust_direction")]
    pub direction: Option<u8>,
    /// `ParentChild` / `CrossLink` / `TreeRoot` / `Forest` / `External` /
    /// `Unknown`, or the numeric enum (0 = ParentChild, 1 = CrossLink, ...).
    #[serde(rename = "TrustType", deserialize_with = "lenient_string")]
    pub ty: Option<String>,
    #[serde(rename = "TrustAttributes", deserialize_with = "lenient_string")]
    pub attributes: Option<String>,
    #[serde(rename = "SidFilteringEnabled", deserialize_with = "lenient_bool")]
    pub sid_filtering: Option<bool>,
    #[serde(rename = "SpoofSIDHistoryBlocked", deserialize_with = "lenient_bool")]
    pub spoof_blocked: Option<bool>,
    #[serde(rename = "TGTDelegationEnabled", deserialize_with = "lenient_bool")]
    pub tgt_delegation: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Record {
    #[serde(rename = "ObjectIdentifier")]
    pub oid: Option<String>,
    /// Kept raw: stored verbatim in the property column and parsed into
    /// [`Props`] for the fields ingest needs.
    #[serde(rename = "Properties")]
    pub props: Option<Box<RawValue>>,
    #[serde(rename = "Aces")]
    pub aces: Option<Vec<Ace>>,
    #[serde(rename = "Members")]
    pub members: Option<Vec<Ref>>,
    #[serde(rename = "PrimaryGroupSID")]
    pub primary_group: Option<String>,
    #[serde(rename = "AllowedToDelegate")]
    pub allowed_to_delegate: Option<Vec<Ref>>,
    #[serde(rename = "AllowedToAct")]
    pub allowed_to_act: Option<Vec<Ref>>,
    #[serde(rename = "HasSIDHistory")]
    pub sid_history: Option<Vec<Ref>>,
    #[serde(rename = "Sessions")]
    pub sessions: Option<Results<Session>>,
    #[serde(rename = "PrivilegedSessions")]
    pub privileged_sessions: Option<Results<Session>>,
    #[serde(rename = "RegistrySessions")]
    pub registry_sessions: Option<Results<Session>>,
    #[serde(rename = "LocalAdmins")]
    pub local_admins: Option<Results<Ref>>,
    #[serde(rename = "RemoteDesktopUsers")]
    pub rdp_users: Option<Results<Ref>>,
    #[serde(rename = "DcomUsers")]
    pub dcom_users: Option<Results<Ref>>,
    #[serde(rename = "PSRemoteUsers")]
    pub psremote_users: Option<Results<Ref>>,
    #[serde(rename = "LocalGroups")]
    pub local_groups: Option<Vec<LocalGroup>>,
    #[serde(rename = "ChildObjects")]
    pub children: Option<Vec<Ref>>,
    #[serde(rename = "ContainedBy")]
    pub contained_by: Option<Ref>,
    #[serde(rename = "Links")]
    pub links: Option<Vec<Link>>,
    #[serde(rename = "Trusts")]
    pub trusts: Option<Vec<Trust>>,
    // ---- ADCS (enterprisecas / rootcas / ntauthstores / issuancepolicies)
    #[serde(rename = "HostingComputer")]
    pub hosting_computer: Option<String>,
    #[serde(rename = "EnabledCertTemplates")]
    pub enabled_templates: Option<Vec<Ref>>,
    #[serde(rename = "CARegistryData")]
    pub ca_registry: Option<CaRegistry>,
    #[serde(rename = "DomainSID")]
    pub domain_sid: Option<String>,
    #[serde(rename = "GroupLink")]
    pub group_link: Option<Ref>,
    // ---- DC certificate-mapping registry values (computers)
    #[serde(rename = "DCRegistryData")]
    pub dc_registry: Option<DcRegistry>,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct Collected<T> {
    #[serde(rename = "Collected")]
    pub collected: Option<bool>,
    #[serde(rename = "Value")]
    pub value: Option<T>,
}

impl<T> Default for Collected<T> {
    fn default() -> Self {
        Self { collected: None, value: None }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CaSecurity {
    #[serde(rename = "Collected")]
    pub collected: Option<bool>,
    #[serde(rename = "Data")]
    pub data: Option<Vec<Ace>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Restriction {
    #[serde(rename = "AccessType")]
    pub access_type: Option<String>,
    #[serde(rename = "Agent")]
    pub agent: Option<Ref>,
    #[serde(rename = "Template")]
    pub template: Option<Ref>,
    #[serde(rename = "AllTemplates")]
    pub all_templates: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct EnrollmentAgentRestrictions {
    #[serde(rename = "Collected")]
    pub collected: Option<bool>,
    #[serde(rename = "Restrictions")]
    pub restrictions: Option<Vec<Restriction>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CaRegistry {
    #[serde(rename = "CASecurity")]
    pub ca_security: Option<CaSecurity>,
    #[serde(rename = "EnrollmentAgentRestrictions")]
    pub enrollment_agent_restrictions: Option<EnrollmentAgentRestrictions>,
    #[serde(rename = "IsUserSpecifiesSanEnabled")]
    pub user_specifies_san: Option<Collected<bool>>,
    #[serde(rename = "RoleSeparationEnabled")]
    pub role_separation: Option<Collected<bool>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct DcRegistry {
    #[serde(rename = "CertificateMappingMethods")]
    pub cert_mapping_methods: Option<Collected<i64>>,
    #[serde(rename = "StrongCertificateBindingEnforcement")]
    pub strong_binding: Option<Collected<i64>>,
}

/// Properties CopperHound derives from top-level record data (as BloodHound
/// does), merged into the stored property object for queries and ESC logic.
fn derived_props(r: &Record) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::Value;
    let mut out = Vec::new();
    if let Some(ca) = &r.ca_registry {
        if let Some(ear) = ca.enrollment_agent_restrictions.as_ref().filter(|e| e.collected == Some(true)) {
            let any = ear.restrictions.as_ref().is_some_and(|r| !r.is_empty());
            out.push(("hasenrollmentagentrestrictions", Value::Bool(any)));
        }
        if let Some(san) = ca.user_specifies_san.as_ref().filter(|c| c.collected == Some(true)) {
            out.push(("isuserspecifiessanenabled", Value::Bool(san.value.unwrap_or(false))));
        }
        if let Some(rs) = ca.role_separation.as_ref().filter(|c| c.collected == Some(true)) {
            out.push(("roleseparationenabled", Value::Bool(rs.value.unwrap_or(false))));
        }
    }
    if let Some(dc) = &r.dc_registry {
        for (key, v) in [
            ("certificatemappingmethodsraw", &dc.cert_mapping_methods),
            ("strongcertificatebindingenforcementraw", &dc.strong_binding),
        ] {
            if let Some(c) = v.as_ref().filter(|c| c.collected == Some(true)) {
                out.push((key, Value::from(c.value.unwrap_or(-1))));
            }
        }
    }
    out
}

fn merge_props(raw: Option<Box<RawValue>>, extra: Vec<(&'static str, serde_json::Value)>) -> Option<Box<str>> {
    if extra.is_empty() {
        return raw.map(Box::<str>::from);
    }
    let mut map: serde_json::Map<String, serde_json::Value> =
        raw.as_deref().and_then(|r| serde_json::from_str(r.get()).ok()).unwrap_or_default();
    for (k, v) in extra {
        map.insert(k.to_string(), v);
    }
    Some(serde_json::Value::Object(map).to_string().into_boxed_str())
}

/// Map a computer-local group (by SID suffix or name) to the edge it implies.
fn local_group_edge(g: &LocalGroup) -> Option<u16> {
    let oid = g.oid.as_deref().unwrap_or("");
    let name = g.name.as_deref().unwrap_or("").to_ascii_uppercase();
    if oid.ends_with("-544") || name.starts_with("ADMINISTRATORS@") {
        Some(ek::ADMIN_TO)
    } else if oid.ends_with("-555") || name.starts_with("REMOTE DESKTOP USERS@") {
        Some(ek::CAN_RDP)
    } else if oid.ends_with("-562") || name.starts_with("DISTRIBUTED COM USERS@") {
        Some(ek::EXECUTE_DCOM)
    } else if oid.ends_with("-580") || name.starts_with("REMOTE MANAGEMENT USERS@") {
        Some(ek::CAN_PSREMOTE)
    } else {
        None
    }
}

/// Ingest-time ADCS edges (structural edges needing the built graph are
/// derived in `postprocess::adcs`).
fn extract_adcs(r: &Record, me: u32, em: &mut Emitter) {
    let k = |n: &str| ch_model::ek_of(n);
    em.scope(me, cat::PUBLISHED_TEMPLATES, r.enabled_templates.is_some());
    for t in r.enabled_templates.iter().flatten() {
        if let Some(t) = em.hint(&t.id, Some(NodeKind::CertTemplate)) {
            em.edge(t, me, k("PublishedTo"));
        }
    }
    em.scope(me, cat::HOSTING, r.hosting_computer.is_some());
    if let Some(host) = r.hosting_computer.as_deref().and_then(|h| em.hint(h, Some(NodeKind::Computer))) {
        em.edge(host, me, k("HostsCAService"));
    }
    if let Some(ca) = &r.ca_registry {
        if let Some(sec) = ca.ca_security.as_ref().filter(|s| s.collected == Some(true)) {
            em.scope(me, cat::CA_SECURITY, true);
            let own = r.oid.as_deref().unwrap_or("");
            for a in sec.data.iter().flatten() {
                let (Some(sid), Some(right)) = (a.principal_sid.as_deref(), a.right_name.as_deref()) else { continue };
                if right.is_empty() || sid.eq_ignore_ascii_case(own) {
                    continue;
                }
                if let Some(p) = em.hint_str(sid, a.principal_type.as_deref()) {
                    let kind = em.kind_id(right);
                    em.edge(p, me, kind);
                }
            }
        }
        if let Some(ear) = ca.enrollment_agent_restrictions.as_ref().filter(|e| e.collected == Some(true)) {
            // agent → template: neither endpoint is this CA, so the edges
            // are unowned (never superseded).
            em.unscoped();
            for rs in ear.restrictions.iter().flatten() {
                if rs.access_type.as_deref() != Some("AccessAllowedCallback") {
                    continue;
                }
                let Some(agent) = rs.agent.as_ref().and_then(|a| em.hint_str(&a.id, a.ty.as_deref())) else { continue };
                let templates: Vec<&Ref> = if rs.all_templates == Some(true) {
                    r.enabled_templates.iter().flatten().collect()
                } else {
                    rs.template.iter().collect()
                };
                for t in templates {
                    if let Some(t) = em.hint(&t.id, Some(NodeKind::CertTemplate)) {
                        em.edge(agent, t, k("DelegatedEnrollmentAgent"));
                    }
                }
            }
        }
    }
    if let Some(dsid) = r.domain_sid.as_deref() {
        let edge = match em.file_kind() {
            Some(NodeKind::RootCa) => Some("RootCAFor"),
            Some(NodeKind::NtAuthStore) => Some("NTAuthStoreFor"),
            _ => None,
        };
        if let (Some(edge), Some(d)) = (edge, em.hint(dsid, Some(NodeKind::Domain))) {
            em.scope(me, cat::DOMAIN_STORE, true);
            em.edge(me, d, k(edge));
        }
    }
    em.scope(me, cat::GROUP_LINK, r.group_link.is_some());
    if let Some(g) = r.group_link.as_ref().and_then(|g| em.hint(&g.id, Some(NodeKind::Group))) {
        em.edge(me, g, k("OIDGroupLink"));
    }
}

/// Edge ownership (see `crate::merge`): a record claims a category when it
/// carries the field (`Aces`, `Members`, …; session and local-group blocks
/// only when `Collected` is true), so a newer collection's record supersedes
/// the edges an older record of the same object had in that category.
pub fn extract(mut r: Record, em: &mut Emitter) {
    let Some(oid) = r.oid.clone() else { return };
    let oid = oid.as_str();
    let p: Props = r
        .props
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .unwrap_or_default();
    let mut fl = 0;
    for (v, f) in [
        (p.enabled, flags::ENABLED),
        (p.highvalue, flags::HIGHVALUE),
        (p.admincount, flags::ADMINCOUNT),
        (p.unconstraineddelegation, flags::UNCONSTRAINED_DELEGATION),
        (p.dontreqpreauth, flags::DONT_REQ_PREAUTH),
        (p.hasspn, flags::HAS_SPN),
    ] {
        if v == Some(true) {
            fl |= f;
        }
    }
    if let Some(d) = p.domain.as_deref() {
        em.note_domain(d);
    }
    let extra = derived_props(&r);
    let raw_props = merge_props(r.props.take(), extra);
    let Some(me) = em.own(oid, None, p.name.as_deref(), fl, raw_props) else {
        return;
    };
    extract_adcs(&r, me, em);

    em.scope(me, cat::MEMBERS, r.members.is_some());
    for m in r.members.iter().flatten() {
        if let Some(x) = em.hint_str(&m.id, m.ty.as_deref()) {
            em.edge(x, me, ek::MEMBER_OF);
        }
    }
    if let Some(g) = r
        .primary_group
        .as_deref()
        .and_then(|g| em.hint(g, Some(NodeKind::Group)))
    {
        em.scope(me, cat::PRIMARY_GROUP, true);
        em.edge(me, g, ek::MEMBER_OF);
    }
    em.scope(me, cat::ACES, r.aces.is_some());
    for a in r.aces.iter().flatten() {
        let (Some(sid), Some(right)) = (a.principal_sid.as_deref(), a.right_name.as_deref()) else {
            continue;
        };
        if right.is_empty() {
            continue;
        }
        if let Some(pr) = em.hint_str(sid, a.principal_type.as_deref()) {
            let k = em.kind_id(right);
            em.edge(pr, me, k);
        }
    }
    em.scope(me, cat::DELEGATE, r.allowed_to_delegate.is_some());
    for t in r.allowed_to_delegate.iter().flatten() {
        if let Some(x) = em.hint_str(&t.id, t.ty.as_deref()) {
            em.edge(me, x, ek::ALLOWED_TO_DELEGATE);
        }
    }
    em.scope(me, cat::ALLOWED_TO_ACT, r.allowed_to_act.is_some());
    for t in r.allowed_to_act.iter().flatten() {
        if let Some(x) = em.hint_str(&t.id, t.ty.as_deref()) {
            em.edge(x, me, ek::ALLOWED_TO_ACT);
        }
    }
    em.scope(me, cat::SID_HISTORY, r.sid_history.is_some());
    for t in r.sid_history.iter().flatten() {
        if let Some(x) = em.hint_str(&t.id, t.ty.as_deref()) {
            em.edge(me, x, ek::HAS_SID_HISTORY);
        }
    }
    for (block, c) in [
        (&r.sessions, cat::SESSIONS),
        (&r.privileged_sessions, cat::PRIV_SESSIONS),
        (&r.registry_sessions, cat::REG_SESSIONS),
    ] {
        em.scope(me, c, block.as_ref().is_some_and(|b| b.collected()));
        for s in block.iter().flat_map(|b| b.0.iter()) {
            let Some(user) = s
                .user
                .as_deref()
                .and_then(|u| em.hint(u, Some(NodeKind::User)))
            else {
                continue;
            };
            let comp = s
                .computer
                .as_deref()
                .and_then(|c| em.hint(c, Some(NodeKind::Computer)))
                .unwrap_or(me);
            em.edge(comp, user, ek::HAS_SESSION);
        }
    }
    for (block, kind, c) in [
        (&r.local_admins, ek::ADMIN_TO, cat::LOCAL_ADMINS),
        (&r.rdp_users, ek::CAN_RDP, cat::LOCAL_RDP),
        (&r.dcom_users, ek::EXECUTE_DCOM, cat::LOCAL_DCOM),
        (&r.psremote_users, ek::CAN_PSREMOTE, cat::LOCAL_PSREMOTE),
    ] {
        em.scope(me, c, block.as_ref().is_some_and(|b| b.collected()));
        for x in block.iter().flat_map(|b| b.0.iter()) {
            if let Some(x) = em.hint_str(&x.id, x.ty.as_deref()) {
                em.edge(x, me, kind);
            }
        }
    }
    for g in r.local_groups.iter().flatten() {
        let Some(kind) = local_group_edge(g) else {
            continue;
        };
        let c = match kind {
            ek::ADMIN_TO => cat::LOCAL_ADMINS,
            ek::CAN_RDP => cat::LOCAL_RDP,
            ek::EXECUTE_DCOM => cat::LOCAL_DCOM,
            _ => cat::LOCAL_PSREMOTE,
        };
        em.scope(me, c, g.collected == Some(true));
        for x in g.results.iter().flatten() {
            if let Some(x) = em.hint_str(&x.id, x.ty.as_deref()) {
                em.edge(x, me, kind);
            }
        }
    }
    em.scope(me, cat::CHILDREN, r.children.is_some());
    for c in r.children.iter().flatten() {
        if let Some(x) = em.hint_str(&c.id, c.ty.as_deref()) {
            em.edge(me, x, ek::CONTAINS);
        }
    }
    if let Some(parent) = r
        .contained_by
        .as_ref()
        .and_then(|c| em.hint_str(&c.id, c.ty.as_deref()))
    {
        em.scope(me, cat::CONTAINED_BY, true);
        em.edge(parent, me, ek::CONTAINS);
    }
    em.scope(me, cat::GP_LINKS, r.links.is_some());
    for l in r.links.iter().flatten() {
        if let Some(gpo) = l
            .guid
            .as_deref()
            .and_then(|g| em.hint(g, Some(NodeKind::Gpo)))
        {
            em.edge(gpo, me, ek::GP_LINK);
        }
    }
    em.scope(me, cat::TRUSTS, r.trusts.is_some());
    for t in r.trusts.iter().flatten() {
        let Some(sid) = t.target_sid.as_deref() else {
            continue;
        };
        let Some(other) = em.hint_named(sid, NodeKind::Domain, t.target_name.as_deref()) else {
            continue;
        };
        // "X TrustedBy Y" means Y trusts X.
        // Outbound on this domain: this trusts other → other TrustedBy this.
        // Inbound: other trusts this → this TrustedBy other.
        let dir = t.direction.unwrap_or(0);
        if dir == 2 || dir == 3 {
            em.edge(other, me, ek::TRUSTED_BY);
            trust_edges(t, me, other, em);
        }
        if dir == 1 || dir == 3 {
            em.edge(me, other, ek::TRUSTED_BY);
            trust_edges(t, other, me, em);
        }
    }
    em.unscoped();
}

/// Trust attribute bits (MS-ADTS 6.1.6.7.9).
const TA_WITHIN_FOREST: u32 = 0x20;
const TA_ENABLE_TGT_DELEGATION: u32 = 0x800;

/// BloodHound CE-style trust edges for "`trusting` trusts `trusted`":
/// `trusting -SameForestTrust|CrossForestTrust-> trusted`, plus the abuse
/// edges in attack direction (`trusted -> trusting`) when the trust's
/// configuration allows them. Records without `TrustType`/`TrustAttributes`
/// (older collectors, ldapdomaindump) only get `TrustedBy`.
fn trust_edges(t: &Trust, trusting: u32, trusted: u32, em: &mut Emitter) {
    let attrs = t.attributes.as_deref().and_then(|a| a.trim().parse::<u32>().ok());
    let ty = t.ty.as_deref().map(|s| s.trim().to_ascii_lowercase());
    let same_forest = match ty.as_deref() {
        Some("0" | "1" | "parentchild" | "crosslink" | "treeroot" | "shortcut") => true,
        Some(_) => attrs.is_some_and(|a| a & TA_WITHIN_FOREST != 0),
        None => match attrs {
            Some(a) => a & TA_WITHIN_FOREST != 0,
            None => return,
        },
    };
    // Unknown SID filtering state counts as filtered (the Windows default).
    let spoofable = !t.spoof_blocked.unwrap_or(t.sid_filtering != Some(false));
    let tgt = t.tgt_delegation.unwrap_or(false) || attrs.is_some_and(|a| a & TA_ENABLE_TGT_DELEGATION != 0);
    emit_trust(em, trusting, trusted, same_forest, spoofable, tgt);
}

/// Emit the trust-type edge and abuse edges for "`trusting` trusts `trusted`".
/// Shared by the SharpHound and raw-LDAP parsers.
pub(crate) fn emit_trust(em: &mut Emitter, trusting: u32, trusted: u32, same_forest: bool, spoofable: bool, tgt_delegation: bool) {
    if same_forest {
        // No SID filtering inside a forest: SameForestTrust is itself the
        // (traversable) compromise edge, so no separate SpoofSIDHistory.
        em.edge(trusting, trusted, em.kind_id("SameForestTrust"));
        return;
    }
    em.edge(trusting, trusted, em.kind_id("CrossForestTrust"));
    if spoofable {
        em.edge(trusted, trusting, em.kind_id("SpoofSIDHistory"));
    }
    if tgt_delegation {
        em.edge(trusted, trusting, em.kind_id("AbuseTGTDelegation"));
    }
}
