//! AD ↔ Entra ID hybrid post-processing (runs when both AD and AzureHound
//! data are loaded; a no-op otherwise). See docs/EDGES.md, "Hybrid".
//!
//! * **Synced identities.** An Entra user with `onPremisesSyncEnabled` is
//!   linked to the AD user whose SID equals `onPremisesSecurityIdentifier`
//!   (BloodHound CE rule), or, when the SID is absent, whose `objectguid`
//!   equals the base64-decoded `onPremisesImmutableId` (default Entra Connect
//!   source anchor). Edges: `User -SyncedToEntraUser-> AZUser` and
//!   `AZUser -SyncedToADUser-> User`, both traversable (password hash sync /
//!   pass-through auth one way, password writeback the other).
//!   Synced groups get `Group -SyncedToEntraGroup-> AZGroup` (traversable:
//!   members of the AD group become members of the cloud group) and
//!   `AZGroup -SyncedToADGroup-> Group` (not traversable: membership of a
//!   synced group is mastered on-premises).
//! * **Entra Connect.** AD sync accounts are users named `MSOL_*` or whose
//!   description says they were created by (Azure) AD / Entra Connect; the
//!   description names the server ("running on computer X"). Entra sync
//!   accounts are users holding the Directory Synchronization Accounts role,
//!   named `Sync_<server>_<id>@…` or displayed as "On-Premises Directory
//!   Synchronization Service Account". The server stores both credentials:
//!   `Computer -EntraConnectCredentials-> account`. The accounts, the server
//!   and the role are Tier Zero ([`tier0_nodes`]). The MSOL account's DCSync /
//!   password-reset power comes from its ACEs (DCSync, ForceChangePassword);
//!   the Entra side's is `AZResetPassword` from the Directory Synchronization
//!   Accounts role to every synced user of its tenant (the sync API can set
//!   any synced user's password hash).
//! * **Seamless SSO.** Whoever holds the AZUREADSSOACC computer account's
//!   Kerberos key can forge a service ticket for any user of its AD domain and
//!   exchange it at Entra ID for a sign-in as the synced cloud user:
//!   `Computer(AZUREADSSOACC) -SeamlessSSO-> AZUser` for every synced user
//!   whose on-prem SID is in that domain. Control over the computer object
//!   (or DCSync) therefore leads to those cloud users. The account is Tier Zero.

use super::ad::domain_of;
use super::azure::{get, props};
use ahash::{AHashMap, AHashSet};
use ch_model::{ek_of, NodeKind, AZURE_DIRECTORY_SYNC_ROLE};
use ch_store::{Edge, Graph};
use serde_json::Value;

const SYNC_DISPLAY_NAME: &str = "On-Premises Directory Synchronization Service Account";

struct Synced {
    id: u32,
    sid: Option<String>,
    immutable: Option<String>,
}

fn str_prop(p: &serde_json::Map<String, Value>, k: &str) -> Option<String> {
    get(p, k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn synced(g: &Graph, kind: NodeKind) -> Vec<Synced> {
    (0..g.node_count() as u32)
        .filter(|&i| g.kind(i) == kind)
        .filter_map(|id| {
            let p = props(g, id);
            if get(&p, "onPremisesSyncEnabled").and_then(Value::as_bool) != Some(true) {
                return None;
            }
            Some(Synced {
                id,
                sid: str_prop(&p, "onPremisesSecurityIdentifier").map(|s| s.to_ascii_uppercase()),
                immutable: str_prop(&p, "onPremisesImmutableId"),
            })
        })
        .collect()
}

/// Standard base64 → bytes (`None` on malformed input).
fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let n = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + n]);
    }
    Some(out)
}

/// `onPremisesImmutableId` (base64 of the AD objectGUID bytes) → GUID string
/// as SharpHound writes `objectguid` (uppercase, mixed-endian per RFC 4122).
pub(crate) fn immutable_id_to_guid(s: &str) -> Option<String> {
    let b = base64(s)?;
    if b.len() != 16 {
        return None;
    }
    Some(format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9],
        b[10..].iter().map(|x| format!("{x:02X}")).collect::<String>()
    ))
}

/// AD objects of `kind` by `objectguid` property (built only when needed).
fn by_guid(g: &Graph, kind: NodeKind) -> AHashMap<String, u32> {
    (0..g.node_count() as u32)
        .filter(|&i| g.kind(i) == kind)
        .filter_map(|i| str_prop(&props(g, i), "objectguid").map(|s| (s.to_ascii_uppercase(), i)))
        .collect()
}

/// Link synced cloud objects to their AD source; returns `(ad, cloud)` pairs.
fn link(g: &Graph, ad_kind: NodeKind, cloud: &[Synced]) -> Vec<(u32, u32)> {
    let guids = if cloud.iter().any(|s| s.sid.is_none() && s.immutable.is_some()) {
        by_guid(g, ad_kind)
    } else {
        AHashMap::new()
    };
    cloud
        .iter()
        .filter_map(|s| {
            let by_sid = s.sid.as_deref().and_then(|sid| g.lookup(sid)).filter(|&a| g.kind(a) == ad_kind);
            let by_anchor = || {
                s.immutable.as_deref().and_then(immutable_id_to_guid).and_then(|guid| guids.get(&guid).copied())
            };
            by_sid.or_else(by_anchor).map(|ad| (ad, s.id))
        })
        .collect()
}

/// Entra Connect / Seamless SSO objects found in the graph.
#[derive(Default)]
struct Hybrid {
    /// AD sync accounts (MSOL_*) with the server named in their description.
    ad_sync: Vec<(u32, Option<String>)>,
    /// Entra sync accounts (Sync_*) with the server named in their UPN.
    entra_sync: Vec<(u32, Option<String>)>,
    /// Directory Synchronization Accounts role nodes.
    sync_roles: Vec<u32>,
    /// AZUREADSSOACC computer accounts.
    sso: Vec<u32>,
}

fn upper_contains(hay: &str, needle: &str) -> bool {
    hay.to_ascii_uppercase().contains(needle)
}

/// "… running on computer HOST configured to …" → `HOST`.
fn host_from_description(desc: &str) -> Option<String> {
    let u = desc.to_ascii_uppercase();
    let at = u.find("RUNNING ON COMPUTER ")? + "RUNNING ON COMPUTER ".len();
    let host: String = u[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.').collect();
    let host = host.trim_end_matches('.').to_string();
    (!host.is_empty()).then_some(host)
}

/// `SYNC_HOST_0123456789AB@TENANT.ONMICROSOFT.COM` → `HOST`.
fn host_from_sync_upn(upn: &str) -> Option<String> {
    let local = upn.to_ascii_uppercase();
    let local = local.split('@').next()?.strip_prefix("SYNC_")?.to_string();
    let (host, id) = local.rsplit_once('_')?;
    (!host.is_empty() && id.len() >= 8 && id.chars().all(|c| c.is_ascii_hexdigit())).then(|| host.to_string())
}

fn detect(g: &Graph) -> Hybrid {
    let mut h = Hybrid::default();
    let has_role = g.edge_kind_id("AZHasRole");
    for id in 0..g.node_count() as u32 {
        match g.kind(id) {
            NodeKind::User => {
                let name = g.name(id).to_ascii_uppercase();
                let p = props(g, id);
                let sam = str_prop(&p, "samaccountname").unwrap_or_default().to_ascii_uppercase();
                let desc = str_prop(&p, "description").unwrap_or_default();
                let by_desc = upper_contains(&desc, "ACTIVE DIRECTORY CONNECT") || upper_contains(&desc, "ENTRA CONNECT");
                if name.starts_with("MSOL_") || sam.starts_with("MSOL_") || by_desc {
                    h.ad_sync.push((id, host_from_description(&desc)));
                }
            }
            NodeKind::Computer => {
                let name = g.name(id).to_ascii_uppercase();
                let sam = str_prop(&props(g, id), "samaccountname").unwrap_or_default().to_ascii_uppercase();
                if name.split('.').next() == Some("AZUREADSSOACC") || sam == "AZUREADSSOACC$" {
                    h.sso.push(id);
                }
            }
            NodeKind::AzRole => {
                let oid = g.oid(id);
                if oid.len() > AZURE_DIRECTORY_SYNC_ROLE.len()
                    && oid.starts_with(AZURE_DIRECTORY_SYNC_ROLE)
                    && oid.as_bytes()[AZURE_DIRECTORY_SYNC_ROLE.len()] == b'@'
                {
                    h.sync_roles.push(id);
                }
            }
            _ => {}
        }
    }
    let mut seen = AHashSet::new();
    let role_holders: Vec<u32> = h
        .sync_roles
        .iter()
        .flat_map(|&r| {
            let (s, k) = g.in_edges(r);
            s.iter().zip(k).filter(|(_, kk)| Some(**kk) == has_role).map(|(&x, _)| x).collect::<Vec<_>>()
        })
        .filter(|&x| g.kind(x) == NodeKind::AzUser)
        .collect();
    for id in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::AzUser) {
        let upn = g.name(id);
        let host = host_from_sync_upn(upn);
        let display = str_prop(&props(g, id), "displayName");
        let by_name = host.is_some() || display.as_deref().is_some_and(|d| d.eq_ignore_ascii_case(SYNC_DISPLAY_NAME));
        if (by_name || role_holders.contains(&id)) && seen.insert(id) {
            h.entra_sync.push((id, host));
        }
    }
    h
}

/// Computer nodes by short host name (first DNS label of the name).
fn computers_by_host(g: &Graph) -> AHashMap<String, Vec<u32>> {
    let mut m: AHashMap<String, Vec<u32>> = AHashMap::new();
    for id in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Computer) {
        if let Some(short) = g.name(id).split('.').next().filter(|s| !s.is_empty()) {
            m.entry(short.to_ascii_uppercase()).or_default().push(id);
        }
    }
    m
}

/// The Entra Connect server named `host`; when several computers share the
/// short name, prefer one in `near`'s domain, else give up.
fn resolve_host(g: &Graph, hosts: &AHashMap<String, Vec<u32>>, host: &str, near: Option<u32>) -> Option<u32> {
    let short = host.split('.').next()?;
    let cands = hosts.get(short)?;
    if let [one] = cands.as_slice() {
        return Some(*one);
    }
    if let Some(full) = cands.iter().copied().find(|&c| g.name(c).eq_ignore_ascii_case(host)) {
        return Some(full);
    }
    let dom = near.and_then(|n| domain_of(g, n))?;
    let same: Vec<u32> = cands.iter().copied().filter(|&c| domain_of(g, c) == Some(dom)).collect();
    (same.len() == 1).then(|| same[0])
}

/// Entra Connect servers referenced by the sync accounts.
fn connect_hosts(g: &Graph, h: &Hybrid) -> Vec<(u32, u32)> {
    if h.ad_sync.iter().chain(&h.entra_sync).all(|(_, host)| host.is_none()) {
        return Vec::new();
    }
    let hosts = computers_by_host(g);
    h.ad_sync
        .iter()
        .map(|(a, host)| (a, host, Some(*a)))
        .chain(h.entra_sync.iter().map(|(a, host)| (a, host, None)))
        .filter_map(|(&acct, host, near)| resolve_host(g, &hosts, host.as_deref()?, near).map(|c| (c, acct)))
        .collect()
}

/// Tier Zero added by the hybrid rules: Entra Connect sync accounts (AD and
/// Entra side) and the server holding their credentials, and AZUREADSSOACC.
pub fn tier0_nodes(g: &Graph) -> Vec<u32> {
    let h = detect(g);
    let mut out: Vec<u32> = h.ad_sync.iter().chain(&h.entra_sync).map(|(a, _)| *a).collect();
    out.extend(&h.sso);
    out.extend(connect_hosts(g, &h).into_iter().map(|(c, _)| c));
    out.sort_unstable();
    out.dedup();
    out
}

pub fn pass(g: &Graph) -> Vec<Edge> {
    let mut out: AHashSet<(u32, u32, u16)> = AHashSet::new();
    let mut emit = |s: u32, d: u32, kind: &str| {
        if s != d {
            out.insert((s, d, ek_of(kind)));
        }
    };

    let users = synced(g, NodeKind::AzUser);
    for (ad, az) in link(g, NodeKind::User, &users) {
        emit(ad, az, "SyncedToEntraUser");
        emit(az, ad, "SyncedToADUser");
    }
    for (ad, az) in link(g, NodeKind::Group, &synced(g, NodeKind::AzGroup)) {
        emit(ad, az, "SyncedToEntraGroup");
        emit(az, ad, "SyncedToADGroup");
    }

    let h = detect(g);
    for (c, acct) in connect_hosts(g, &h) {
        emit(c, acct, "EntraConnectCredentials");
    }

    // Seamless SSO: AZUREADSSOACC → synced users of its AD domain.
    for &sso in &h.sso {
        let dom = domain_of(g, sso).map(|d| g.oid(d).to_string()).or_else(|| {
            let o = g.oid(sso);
            o.starts_with("S-1-5-21-").then(|| o.rsplit_once('-').map(|(p, _)| p.to_string())).flatten()
        });
        let Some(prefix) = dom.map(|d| format!("{d}-")) else { continue };
        for u in users.iter().filter(|u| u.sid.as_deref().is_some_and(|s| s.starts_with(&prefix))) {
            emit(sso, u.id, "SeamlessSSO");
        }
    }

    // Directory Synchronization Accounts role → synced users of its tenant.
    if !h.sync_roles.is_empty() {
        let contains = ek_of("AZContains");
        let synced_ids: AHashSet<u32> = users.iter().map(|u| u.id).collect();
        for &r in &h.sync_roles {
            let Some(tenant) = g.oid(r).split_once('@').and_then(|(_, t)| g.lookup(t)) else { continue };
            let (ds, ks) = g.out_edges(tenant);
            for (&u, _) in ds.iter().zip(ks).filter(|(u, k)| **k == contains && synced_ids.contains(u)) {
                emit(r, u, "AZResetPassword");
            }
        }
    }
    out.into_iter().map(|(s, d, k)| Edge::new(s, d, k)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_id_decodes_to_objectguid() {
        // objectGUID 9F3A3E6C-1B7D-4C4E-9A0B-3F1D2E4C5B6A in AD byte order.
        let bytes = [0x6C, 0x3E, 0x3A, 0x9F, 0x7D, 0x1B, 0x4E, 0x4C, 0x9A, 0x0B, 0x3F, 0x1D, 0x2E, 0x4C, 0x5B, 0x6A];
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut enc = String::new();
        for c in bytes.chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
            for i in 0..=c.len() {
                enc.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        enc.push_str("==");
        assert_eq!(immutable_id_to_guid(&enc).as_deref(), Some("9F3A3E6C-1B7D-4C4E-9A0B-3F1D2E4C5B6A"));
        assert_eq!(immutable_id_to_guid("not base64!"), None);
        assert_eq!(immutable_id_to_guid("QUJD"), None, "wrong length");
    }

    #[test]
    fn sync_account_names() {
        assert_eq!(host_from_sync_upn("Sync_AADC01_1a2b3c4d5e6f@contoso.onmicrosoft.com").as_deref(), Some("AADC01"));
        assert_eq!(host_from_sync_upn("sync_team@contoso.com"), None);
        assert_eq!(
            host_from_description(
                "Account created by Microsoft Azure Active Directory Connect with installation identifier 1a2b running on computer AADC01 configured to synchronize to tenant contoso.onmicrosoft.com."
            )
            .as_deref(),
            Some("AADC01")
        );
    }
}
