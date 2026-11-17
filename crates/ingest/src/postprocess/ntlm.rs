//! NTLM relay edges (BloodHound CE semantics, independently implemented):
//! `Authenticated Users -CoerceAndRelayNTLMTo*-> computer`. Any authenticated
//! principal can coerce the computer to authenticate (PetitPotam, PrinterBug,
//! DFSCoerce, WebDAV) and relay the NTLM authentication to a service that
//! accepts it, taking over the computer account or a host it administers.
//!
//! The coercion victim must not restrict outgoing NTLM: `restrictoutboundntlm`
//! must be collected and false (SharpHound `NTLMRegistryData`; a missing value
//! counts as restricted, so no edge is guessed). A victim in Protected Users is
//! skipped when its domain's functional level is 2012 R2 or later (Protected
//! Users members do not use NTLM there).
//!
//! * **SMB:** the victim's account is a local administrator (`AdminTo`,
//!   directly or through groups) of another computer whose `smbsigning` is
//!   collected and false.
//! * **LDAP:** the victim runs the WebClient service (`webclientrunning`), so
//!   HTTP coercion gives NTLM without signing, and a DC of its domain other
//!   than itself has LDAP available (`ldapavailable` / `ldapenabled`) without
//!   required signing (`ldapsigning` false).
//! * **LDAPS:** WebClient as above, and a DC of its domain has LDAPS
//!   (`ldapsavailable` / `ldapsenabled`) without channel binding (`ldapsepa`
//!   false).
//!
//! The AD CS relays (ESC8 web enrollment, ESC11 RPC) need the CA and template
//! rules and are emitted by the ADCS pass with [`Ntlm::victim`].

use super::ad::domain_of;
use super::Members;
use ahash::{AHashMap, AHashSet};
use ch_model::{ek, ek_of, flags, NodeKind};
use ch_store::{Edge, Graph};
use serde_json::{Map, Value};

type Props = Map<String, Value>;

/// Functional levels before 2012 R2: Protected Users does not block NTLM.
const OLD_LEVELS: &[&str] = &["2000 MIXED/NATIVE", "2003 INTERIM", "2003", "2008", "2008 R2", "2012", "2000"];

/// Property keys the pass reads; a node whose raw properties contain none of
/// them is not parsed.
const KEYS: &[&str] = &["restrictoutboundntlm", "smbsigning", "webclientrunning", "ldapsigning", "ldapsepa"];

fn props_of(g: &Graph, id: u32) -> Props {
    let raw = g.props(id);
    if !KEYS.iter().any(|k| raw.contains(k)) {
        return Props::new();
    }
    serde_json::from_str(raw).unwrap_or_default()
}

fn b(p: &Props, k: &str) -> Option<bool> {
    p.get(k).and_then(Value::as_bool)
}

/// The first present key of `keys` as a bool.
fn b_any(p: &Props, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|k| b(p, k))
}

pub(crate) fn ldap_open(p: &Props) -> bool {
    b(p, "ldapsigning") == Some(false) && b_any(p, &["ldapavailable", "ldapenabled"]) == Some(true)
}

pub(crate) fn ldaps_open(p: &Props) -> bool {
    b(p, "ldapsepa") == Some(false) && b_any(p, &["ldapsavailable", "ldapsenabled"]) == Some(true)
}

/// The domain of a principal from its SID prefix, without parsing properties.
fn sid_domain(g: &Graph, id: u32) -> Option<u32> {
    let oid = g.oid(id);
    let (prefix, _) = oid.starts_with("S-1-5-21-").then(|| oid.rsplit_once('-')).flatten()?;
    g.lookup(prefix).filter(|&d| g.kind(d) == NodeKind::Domain)
}

/// Authenticated Users (`S-1-5-11`, optionally prefixed with the domain name).
pub(crate) fn is_auth_users(oid: &str) -> bool {
    oid == "S-1-5-11" || oid.strip_suffix("S-1-5-11").is_some_and(|p| p.ends_with('-'))
}

/// Shared relay context: per-domain Authenticated Users, DCs and the victim filter.
pub(crate) struct Ntlm<'g> {
    g: &'g Graph,
    pub props: AHashMap<u32, Props>,
    /// Domain → its Authenticated Users group.
    auth_users: AHashMap<u32, u32>,
    /// Domain → its DCs.
    pub dcs: AHashMap<u32, Vec<u32>>,
    domain: AHashMap<u32, u32>,
    /// Computers excluded as victims by Protected Users.
    protected: AHashSet<u32>,
}

impl<'g> Ntlm<'g> {
    pub fn new(g: &'g Graph, m: &Members<'g>) -> Self {
        let mut props = AHashMap::new();
        let mut domain = AHashMap::new();
        let mut dcs: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let domains: Vec<u32> = (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Domain).collect();
        let dc_groups: AHashMap<u32, u32> =
            domains.iter().filter_map(|&d| g.lookup(&format!("{}-516", g.oid(d))).map(|grp| (grp, d))).collect();
        for c in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Computer) {
            let p = props_of(g, c);
            let Some(d) = sid_domain(g, c).or_else(|| domain_of(g, c)) else {
                props.insert(c, p);
                continue;
            };
            domain.insert(c, d);
            let (ds, ks) = g.out_edges(c);
            let in_dc_group = ds.iter().zip(ks).any(|(x, &k)| k == ek::MEMBER_OF && dc_groups.get(x) == Some(&d));
            if in_dc_group || super::raw_bool(g.props(c), "isdc") == Some(true) {
                dcs.entry(d).or_default().push(c);
            }
            props.insert(c, p);
        }
        let mut auth_users = AHashMap::new();
        for grp in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Group && is_auth_users(g.oid(i))) {
            let oid = g.oid(grp);
            let prefix = oid.strip_suffix("-S-1-5-11").unwrap_or("");
            let d = domain_of(g, grp).or_else(|| {
                (!prefix.is_empty())
                    .then(|| domains.iter().copied().find(|&d| g.name(d).eq_ignore_ascii_case(prefix)))
                    .flatten()
            });
            if let Some(d) = d {
                auth_users.entry(d).or_insert(grp);
            }
        }
        // Protected Users (RID 525) members, on domains at 2012 R2 or later.
        let mut protected = AHashSet::new();
        for &d in &domains {
            let level = serde_json::from_str::<Props>(g.props(d))
                .ok()
                .and_then(|p| p.get("functionallevel").and_then(Value::as_str).map(str::to_ascii_uppercase));
            if level.as_deref().is_some_and(|l| OLD_LEVELS.contains(&l)) {
                continue;
            }
            if let Some(pu) = g.lookup(&format!("{}-525", g.oid(d))) {
                protected.extend(m.members(pu).iter().copied().filter(|&x| g.kind(x) == NodeKind::Computer));
            }
        }
        Ntlm { g, props, auth_users, dcs, domain, protected }
    }

    pub fn p(&self, id: u32) -> &Props {
        static EMPTY: std::sync::OnceLock<Props> = std::sync::OnceLock::new();
        self.props.get(&id).unwrap_or_else(|| EMPTY.get_or_init(Props::new))
    }

    pub fn auth_users(&self, d: u32) -> Option<u32> {
        self.auth_users.get(&d).copied()
    }

    pub fn domain(&self, c: u32) -> Option<u32> {
        self.domain.get(&c).copied()
    }

    /// A computer that can be coerced into NTLM authentication, and the
    /// Authenticated Users group of its domain (the edge source).
    pub fn victim(&self, c: u32) -> Option<u32> {
        if self.g.kind(c) != NodeKind::Computer
            || !self.g.has_flag(c, flags::ENABLED)
            || b(self.p(c), "restrictoutboundntlm") != Some(false)
            || self.protected.contains(&c)
        {
            return None;
        }
        self.auth_users(self.domain(c)?)
    }

    /// A DC of `c`'s domain other than `c` matching `open`.
    pub fn relay_dc(&self, c: u32, open: fn(&Props) -> bool) -> Option<u32> {
        let d = self.domain(c)?;
        self.dcs.get(&d)?.iter().copied().find(|&dc| dc != c && open(self.p(dc)))
    }
}

/// Why a relay edge was emitted (for edge composition).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Relay {
    /// SMB: the victim administers `host`, which does not require signing.
    Smb { host: u32 },
    /// LDAP / LDAPS: `dc` accepts the relay.
    Ldap { dc: u32 },
}

pub fn pass(g: &Graph) -> Vec<Edge> {
    run(g, None).0
}

/// The rule matches behind relay edge `want` (SMB / LDAP / LDAPS).
pub(crate) fn witnesses(g: &Graph, want: (u32, u32, u16)) -> Vec<Relay> {
    run(g, Some(want)).1
}

fn run(g: &Graph, want: Option<(u32, u32, u16)>) -> (Vec<Edge>, Vec<Relay>) {
    let m = Members::new(g);
    let cx = Ntlm::new(g, &m);
    let mut out: AHashSet<(u32, u32, u16)> = AHashSet::new();
    let mut whys = Vec::new();
    let mut emit = |s: u32, d: u32, k: u16, why: Relay| {
        if want == Some((s, d, k)) && whys.len() < 8 && !whys.contains(&why) {
            whys.push(why);
        }
        out.insert((s, d, k));
    };
    let (smb, ldap, ldaps) =
        (ek_of("CoerceAndRelayNTLMToSMB"), ek_of("CoerceAndRelayNTLMToLDAP"), ek_of("CoerceAndRelayNTLMToLDAPS"));

    // SMB: hosts without SMB signing, and the computers that administer them.
    let mut hosts: Vec<u32> = cx.props.iter().filter(|(_, p)| b(p, "smbsigning") == Some(false)).map(|(&c, _)| c).collect();
    hosts.sort_unstable();
    for host in hosts {
        let (ss, ks) = g.in_edges(host);
        let mut admins: Vec<u32> = Vec::new();
        for (&s, &k) in ss.iter().zip(ks) {
            if k != ek::ADMIN_TO {
                continue;
            }
            if m.is_group(s) {
                admins.extend(m.members(s).iter().copied().filter(|&x| g.kind(x) == NodeKind::Computer));
            } else if g.kind(s) == NodeKind::Computer {
                admins.push(s);
            }
        }
        admins.sort_unstable();
        admins.dedup();
        for v in admins.into_iter().filter(|&v| v != host) {
            if let Some(au) = cx.victim(v) {
                emit(au, v, smb, Relay::Smb { host });
            }
        }
    }

    // LDAP / LDAPS over WebDAV coercion.
    let mut webdav: Vec<u32> = cx.props.iter().filter(|(_, p)| b(p, "webclientrunning") == Some(true)).map(|(&c, _)| c).collect();
    webdav.sort_unstable();
    for v in webdav {
        let Some(au) = cx.victim(v) else { continue };
        if let Some(dc) = cx.relay_dc(v, ldap_open) {
            emit(au, v, ldap, Relay::Ldap { dc });
        }
        if let Some(dc) = cx.relay_dc(v, ldaps_open) {
            emit(au, v, ldaps, Relay::Ldap { dc });
        }
    }
    (out.into_iter().map(|(s, d, k)| Edge::new(s, d, k)).collect(), whys)
}
