//! Edge composition: why a derived edge exists, as the collected edges and
//! object facts it was derived from (BloodHound CE's "edge composition").
//!
//! The explanation is rebuilt from the loaded graph on demand, so nothing is
//! stored at ingest. ADCS edges replay the ADCS pass and record the rule match
//! that emitted the edge ([`adcs::Why`]), so the explanation uses the same
//! template, CA and victim the rule used. The other kinds have simple rules
//! (replication rights, role holders, trust paths) that are re-checked here
//! against the graph.
//!
//! A [`Composition`] is `complete` when every requirement of the rule was found
//! in the graph. [`check_all`] verifies that for every derived edge of a graph
//! (used by the tests).

use super::ad::{domain_of, netbios_name, sam_of, trust_pairs};
use super::adcs::{self, Why};
use super::azure::{self, role};
use super::repl::is_everyone;
use super::Forests;
use ahash::{AHashMap, AHashSet};
use ch_model::{ek, flags, NodeKind};
use ch_store::Graph;
use serde_json::{Map, Value};
use std::collections::VecDeque;

/// Edge kinds derived by post-processing that can be explained.
pub const COMPOSITE_KINDS: &[&str] = &[
    "DCSync",
    "SyncLAPSPassword",
    "CoerceToTGT",
    "HasTrustKeys",
    "GoldenCert",
    "ADCSESC1",
    "ADCSESC3",
    "ADCSESC4",
    "ADCSESC6a",
    "ADCSESC6b",
    "ADCSESC9a",
    "ADCSESC9b",
    "ADCSESC10a",
    "ADCSESC10b",
    "ADCSESC13",
    "AZGlobalAdmin",
    "AZPrivilegedRoleAdmin",
    "AZPrivilegedAuthAdmin",
    "AZAddMembers",
    "AZAddSecret",
    "AZAddOwner",
    "AZExecuteCommand",
    "AZResetPassword",
    "AZMGAddSecret",
    "AZMGAddOwner",
    "AZMGAddMember",
    "AZMGGrantAppRoles",
    "AZMGGrantRole",
    "SyncedToEntraUser",
    "SyncedToADUser",
    "SyncedToEntraGroup",
    "SyncedToADGroup",
    "EntraConnectCredentials",
    "SeamlessSSO",
];

pub fn is_composite(kind: &str) -> bool {
    COMPOSITE_KINDS.contains(&kind)
}

/// The edges and facts behind one derived edge.
#[derive(Debug, Clone, Default)]
pub struct Composition {
    /// Nodes to draw (edge endpoints plus nodes that only carry a fact).
    pub nodes: Vec<u32>,
    /// Supporting edges, all present in the graph.
    pub edges: Vec<(u32, u32, u16)>,
    /// Plain-language facts: object properties the rule checked, implicit
    /// memberships, and anything that could not be shown as an edge.
    pub notes: Vec<String>,
    /// Every requirement of the rule was found in the graph.
    pub complete: bool,
}

/// Explains the edge `src -kind-> dst`. `None` when `kind` is not a derived
/// kind or the edge is not in the graph.
pub fn compose(g: &Graph, src: u32, dst: u32, kind: u16) -> Option<Composition> {
    let name = g.edge_kind_name(kind).to_string();
    if !is_composite(&name) || (src as usize) >= g.node_count() || (dst as usize) >= g.node_count() {
        return None;
    }
    let (ds, ks) = g.out_edges(src);
    if !ds.iter().zip(ks).any(|(&d, &k)| d == dst && k == kind) {
        return None;
    }
    let mut b = B::new(g);
    b.node(src);
    b.node(dst);
    match name.as_str() {
        "DCSync" => b.replication(src, dst, &[("GetChanges", ek::GET_CHANGES), ("GetChangesAll", ek::GET_CHANGES_ALL)]),
        "SyncLAPSPassword" => b.sync_laps(src, dst),
        "CoerceToTGT" => b.coerce_to_tgt(src, dst),
        "HasTrustKeys" => b.trust_keys(src, dst),
        "SyncedToEntraUser" | "SyncedToADUser" | "SyncedToEntraGroup" | "SyncedToADGroup" => b.synced(src, dst, &name),
        "EntraConnectCredentials" => b.connect_credentials(src, dst),
        "SeamlessSSO" => b.seamless_sso(src, dst),
        n if n.starts_with("AZMG") => b.ms_graph(src, dst, n),
        n if n.starts_with("AZ") => b.azure_role(src, dst, n),
        _ => b.adcs(src, dst, kind, &name),
    }
    Some(b.finish())
}

/// Every derived edge of `g` whose composition is incomplete, as
/// `"src -kind-> dst: notes"` lines.
pub fn check_all(g: &Graph) -> Vec<String> {
    let kinds: AHashSet<u16> = COMPOSITE_KINDS.iter().filter_map(|k| g.edge_kind_id(k)).collect();
    let mut bad = Vec::new();
    for s in 0..g.node_count() as u32 {
        let (ds, ks) = g.out_edges(s);
        for (&d, &k) in ds.iter().zip(ks) {
            if kinds.contains(&k) {
                let c = compose(g, s, d, k).expect("edge exists");
                if !c.complete {
                    bad.push(format!("{} -{}-> {}: {}", g.name(s), g.edge_kind_name(k), g.name(d), c.notes.join(" | ")));
                }
            }
        }
    }
    bad
}

type Props = Map<String, Value>;

fn props(g: &Graph, id: u32) -> Props {
    serde_json::from_str(g.props(id)).unwrap_or_default()
}

/// Case-insensitive property lookup rendered for a note.
fn prop_text(p: &Props, key: &str) -> Option<String> {
    let v = p.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)?;
    Some(match v {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    })
}

/// Composition builder.
struct B<'g> {
    g: &'g Graph,
    nodes: Vec<u32>,
    edges: Vec<(u32, u32, u16)>,
    notes: Vec<String>,
    complete: bool,
    member_kinds: Vec<u16>,
    specials: Option<Vec<u32>>,
}

/// Membership searches stop after this many groups (a principal's groups are
/// normally far fewer).
const MAX_GROUPS: usize = 200_000;

impl<'g> B<'g> {
    fn new(g: &'g Graph) -> Self {
        let mut member_kinds = vec![ek::MEMBER_OF];
        member_kinds.extend(g.edge_kind_id("AZMemberOf"));
        B { g, nodes: Vec::new(), edges: Vec::new(), notes: Vec::new(), complete: true, member_kinds, specials: None }
    }

    fn finish(mut self) -> Composition {
        let mut seen = AHashSet::new();
        self.edges.retain(|e| seen.insert(*e));
        let mut nodes = std::mem::take(&mut self.nodes);
        for &(s, d, _) in &self.edges {
            nodes.push(s);
            nodes.push(d);
        }
        let mut seen = AHashSet::new();
        nodes.retain(|n| seen.insert(*n));
        let mut seen = AHashSet::new();
        self.notes.retain(|n| seen.insert(n.clone()));
        Composition { nodes, edges: self.edges, notes: self.notes, complete: self.complete }
    }

    fn name(&self, id: u32) -> String {
        let n = self.g.name(id);
        if n.is_empty() { self.g.oid(id).to_string() } else { n.to_string() }
    }
    fn kid(&self, name: &str) -> Option<u16> {
        self.g.edge_kind_id(name)
    }
    fn node(&mut self, id: u32) {
        self.nodes.push(id);
    }
    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
    fn missing(&mut self, s: impl Into<String>) {
        self.complete = false;
        self.notes.push(format!("Not found in the graph: {}", s.into()));
    }

    /// Adds `s -kind-> d` when present; true when it is.
    fn edge_if(&mut self, s: u32, d: u32, kind: &str) -> bool {
        let Some(k) = self.kid(kind) else { return false };
        let (ds, ks) = self.g.out_edges(s);
        let found = ds.iter().zip(ks).any(|(&x, &kk)| x == d && kk == k);
        if found {
            self.edges.push((s, d, k));
        }
        found
    }
    fn require_edge(&mut self, s: u32, d: u32, kind: &str) {
        if !self.edge_if(s, d, kind) {
            let msg = format!("{} -{kind}-> {}", self.name(s), self.name(d));
            self.missing(msg);
        }
    }
    fn targets(&self, x: u32, kind: &str) -> Vec<u32> {
        let Some(k) = self.kid(kind) else { return Vec::new() };
        let (ds, ks) = self.g.out_edges(x);
        ds.iter().zip(ks).filter(|(_, &kk)| kk == k).map(|(&d, _)| d).collect()
    }
    fn sources(&self, x: u32, kind: &str) -> Vec<u32> {
        let Some(k) = self.kid(kind) else { return Vec::new() };
        let (ss, ks) = self.g.in_edges(x);
        ss.iter().zip(ks).filter(|(_, &kk)| kk == k).map(|(&s, _)| s).collect()
    }

    /// Authenticated Users / Everyone groups.
    fn specials(&mut self) -> Vec<u32> {
        if self.specials.is_none() {
            let g = self.g;
            self.specials =
                Some((0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Group && is_everyone(g.oid(i))).collect());
        }
        self.specials.clone().unwrap_or_default()
    }

    /// Shortest `from -MemberOf*-> x -k-> target` with `k` in `kinds`, as the
    /// edges of the chain.
    fn membership_path(&self, from: u32, target: u32, kinds: &[u16]) -> Option<Vec<(u32, u32, u16)>> {
        let g = self.g;
        // Group → (the member it was reached from, membership edge kind).
        let mut parent: AHashMap<u32, (u32, u16)> = AHashMap::new();
        let mut queue = VecDeque::from([from]);
        let mut seen = AHashSet::from([from]);
        while let Some(x) = queue.pop_front() {
            let (ds, ks) = g.out_edges(x);
            if let Some((_, &k)) = ds.iter().zip(ks).find(|(&d, k)| d == target && kinds.contains(k)) {
                let mut chain = vec![(x, target, k)];
                let mut cur = x;
                while let Some(&(p, mk)) = parent.get(&cur) {
                    chain.push((p, cur, mk));
                    cur = p;
                }
                chain.reverse();
                return Some(chain);
            }
            if seen.len() > MAX_GROUPS {
                return None;
            }
            for (&d, &k) in ds.iter().zip(ks) {
                if self.member_kinds.contains(&k) && seen.insert(d) {
                    parent.insert(d, (x, k));
                    queue.push_back(d);
                }
            }
        }
        None
    }

    /// Proves that `subject` holds one of `kinds` on `target`, directly, through
    /// group membership, or through Authenticated Users / Everyone (every
    /// principal is implicitly a member; collectors do not record it).
    fn holds(&mut self, subject: u32, target: u32, kinds: &[&str]) -> bool {
        let ks: Vec<u16> = kinds.iter().filter_map(|k| self.kid(k)).collect();
        if let Some(chain) = self.membership_path(subject, target, &ks) {
            self.edges.extend(chain);
            return true;
        }
        for sp in self.specials() {
            if let Some(chain) = self.membership_path(sp, target, &ks) {
                self.edges.extend(chain);
                let msg = format!(
                    "{} is implicitly a member of {} (every authenticated principal is; collectors do not record that membership).",
                    self.name(subject),
                    self.name(sp)
                );
                self.note(msg);
                return true;
            }
        }
        let msg = format!("{} holding {} on {}", self.name(subject), kinds.join(" / "), self.name(target));
        self.missing(msg);
        false
    }

    // ------------------------------------------------------------ AD rules

    fn replication(&mut self, s: u32, d: u32, rights: &[(&str, u16)]) {
        for (name, _) in rights {
            self.holds(s, d, &[name]);
        }
        let list = rights.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(" + ");
        let msg = format!(
            "{list} on {} are held by {} itself or through its groups. The edge starts at the first principal in a membership chain that holds both; members below it reach it through MemberOf.",
            self.name(d),
            self.name(s)
        );
        self.note(msg);
    }

    fn sync_laps(&mut self, s: u32, c: u32) {
        let Some(d) = domain_of(self.g, c) else {
            let msg = format!("domain of {}", self.name(c));
            return self.missing(msg);
        };
        self.node(d);
        self.replication(s, d, &[("GetChanges", ek::GET_CHANGES), ("GetChangesInFilteredSet", ek::GET_CHANGES_IN_FILTERED_SET)]);
        let msg = format!("{} has LAPS (haslaps = true); its password is replicated with the filtered attribute set.", self.name(c));
        self.note(msg);
    }

    fn coerce_to_tgt(&mut self, s: u32, t: u32) {
        let g = self.g;
        let ok = g.has_flag(s, flags::ENABLED) && g.has_flag(s, flags::UNCONSTRAINED_DELEGATION);
        if ok {
            let msg = format!("{} is enabled and trusted for unconstrained delegation.", self.name(s));
            self.note(msg);
        } else {
            let msg = format!("{} enabled with unconstrained delegation", self.name(s));
            self.missing(msg);
        }
        let Some(dom) = domain_of(g, s) else {
            let msg = format!("domain of {}", self.name(s));
            return self.missing(msg);
        };
        self.node(dom);
        if dom == t {
            let msg = format!("{} belongs to {}: coerce one of its DCs to authenticate and capture the DC's TGT.", self.name(s), self.name(t));
            return self.note(msg);
        }
        let msg = format!("{} belongs to {}.", self.name(s), self.name(dom));
        self.note(msg);
        // dom → t over intra-forest trusts (either direction) and at most one
        // AbuseTGTDelegation hop (a trust with TGT delegation enabled).
        let (sft, atd) = (self.kid("SameForestTrust"), self.kid("AbuseTGTDelegation"));
        // (domain, delegation hop used) → (previous state, edge taken).
        type State = (u32, bool);
        type Hop = (State, (u32, u32, u16));
        let mut parent: AHashMap<State, Hop> = AHashMap::new();
        let mut queue = VecDeque::from([(dom, false)]);
        let mut seen = AHashSet::from([(dom, false)]);
        let mut found = None;
        while let Some((x, used)) = queue.pop_front() {
            if x == t {
                found = Some((x, used));
                break;
            }
            let (os, oks) = g.out_edges(x);
            let (is, iks) = g.in_edges(x);
            let mut next: Vec<Hop> = Vec::new();
            for (&y, &k) in os.iter().zip(oks) {
                if Some(k) == sft {
                    next.push(((y, used), (x, y, k)));
                } else if Some(k) == atd && !used {
                    next.push(((y, true), (x, y, k)));
                }
            }
            for (&y, &k) in is.iter().zip(iks) {
                if Some(k) == sft {
                    next.push(((y, used), (y, x, k)));
                }
            }
            for (st, e) in next {
                if g.kind(st.0) == NodeKind::Domain && seen.insert(st) {
                    parent.insert(st, ((x, used), e));
                    queue.push_back(st);
                }
            }
        }
        match found {
            Some(mut cur) => {
                while let Some(&(p, e)) = parent.get(&cur) {
                    self.edges.push(e);
                    cur = p;
                }
                let msg = "TGTs are delegable inside a forest and across trusts with TGT delegation enabled, so the captured TGT works in the target domain.";
                self.note(msg);
            }
            None => {
                let msg = format!("a trust path from {} to {}", self.name(dom), self.name(t));
                self.missing(msg);
            }
        }
    }

    fn trust_keys(&mut self, a: u32, acct: u32) {
        let g = self.g;
        let Some(b) = domain_of(g, acct) else {
            let msg = format!("domain of {}", self.name(acct));
            return self.missing(msg);
        };
        if !trust_pairs(g).contains(&(a, b)) {
            let msg = format!("a trust from {} to {}", self.name(a), self.name(b));
            return self.missing(msg);
        }
        let shown = ["SameForestTrust", "CrossForestTrust"].iter().any(|k| self.edge_if(a, b, k)) || self.edge_if(b, a, "TrustedBy");
        if !shown {
            let msg = format!("a trust edge between {} and {}", self.name(a), self.name(b));
            self.missing(msg);
        }
        let nb = netbios_name(g, a).unwrap_or_default();
        let msg = format!(
            "{} trusts {}, which keeps the trust account {} ({}) for it; the account's key is the trust key stored in {}'s trusted domain object.",
            self.name(a),
            self.name(b),
            self.name(acct),
            sam_of(g, acct),
            self.name(a)
        );
        self.note(msg);
        let msg = format!("The account was matched by NetBIOS name {nb} (netbios / flatname property, else the first label of the DNS name).");
        self.note(msg);
    }

    // ---------------------------------------------------------- ADCS rules

    /// The target domain's CA chain: an enabled host, the chain to a root CA
    /// trusted for the domain, and the CA in the domain's NTAuth store.
    fn ca_chain(&mut self, e: u32, d: u32) {
        let g = self.g;
        let host = self.sources(e, "HostsCAService").into_iter().find(|&h| g.kind(h) == NodeKind::Computer && g.has_flag(h, flags::ENABLED));
        match host {
            Some(h) => {
                self.edge_if(h, e, "HostsCAService");
            }
            None => {
                let msg = format!("an enabled computer hosting {}", self.name(e));
                self.missing(msg);
            }
        }
        // e -(IssuedSignedBy | EnterpriseCAFor)*-> RootCA -RootCAFor-> d
        let kinds: Vec<u16> = ["IssuedSignedBy", "EnterpriseCAFor"].iter().filter_map(|k| self.kid(k)).collect();
        let root_for = self.kid("RootCAFor");
        let mut parent: AHashMap<u32, (u32, u16)> = AHashMap::new();
        let mut queue = VecDeque::from([e]);
        let mut seen = AHashSet::from([e]);
        let mut root = None;
        while let Some(x) = queue.pop_front() {
            if g.kind(x) == NodeKind::RootCa {
                let (ds, ks) = g.out_edges(x);
                if ds.iter().zip(ks).any(|(&y, &k)| y == d && Some(k) == root_for) {
                    root = Some(x);
                    break;
                }
                continue;
            }
            let (ds, ks) = g.out_edges(x);
            for (&y, &k) in ds.iter().zip(ks) {
                if kinds.contains(&k) && seen.insert(y) && matches!(g.kind(y), NodeKind::RootCa | NodeKind::EnterpriseCa | NodeKind::AiaCa) {
                    parent.insert(y, (x, k));
                    queue.push_back(y);
                }
            }
        }
        match root {
            Some(r) => {
                self.edge_if(r, d, "RootCAFor");
                let mut cur = r;
                while let Some(&(p, k)) = parent.get(&cur) {
                    self.edges.push((p, cur, k));
                    cur = p;
                }
            }
            None => {
                let msg = format!("a certificate chain from {} to a root CA trusted for {}", self.name(e), self.name(d));
                self.missing(msg);
            }
        }
        let store = self.targets(e, "TrustedForNTAuth").into_iter().find(|&st| self.targets(st, "NTAuthStoreFor").contains(&d));
        match store {
            Some(st) => {
                self.edge_if(e, st, "TrustedForNTAuth");
                self.edge_if(st, d, "NTAuthStoreFor");
            }
            None => {
                let msg = format!("{} in the NTAuth store of {}", self.name(e), self.name(d));
                self.missing(msg);
            }
        }
    }

    /// A domain the CA chains to (ESC13 targets a group, not a domain).
    fn chained_domain(&self, e: u32) -> Option<u32> {
        // Any domain whose NTAuth store trusts e; ca_chain then verifies the root.
        self.targets(e, "TrustedForNTAuth").into_iter().flat_map(|st| self.targets(st, "NTAuthStoreFor")).next()
    }

    fn template_enroll(&mut self, p: u32, t: u32) {
        self.holds(p, t, &["Enroll", "GenericAll", "AllExtendedRights"]);
    }
    fn ca_enroll(&mut self, p: u32, e: u32) {
        self.holds(p, e, &["Enroll"]);
    }

    fn template_facts(&mut self, t: u32, keys: &[&str]) {
        let p = props(self.g, t);
        let facts: Vec<String> = keys.iter().filter_map(|k| prop_text(&p, k).map(|v| format!("{k} = {v}"))).collect();
        if !facts.is_empty() {
            let msg = format!("Template {}: {}.", self.name(t), facts.join(", "));
            self.note(msg);
        }
    }
    fn ca_san_fact(&mut self, e: u32) {
        let msg = format!("{} allows requester-specified SANs (EDITF_ATTRIBUTESUBJECTALTNAME2).", self.name(e));
        self.note(msg);
    }
    fn dc_fact(&mut self, d: u32, upn: bool) {
        let forests = Forests::new(self.g);
        let dc = if upn { adcs::upn_mapping_dc(self.g, &forests, d) } else { adcs::weak_binding_dc(self.g, &forests, d) };
        match dc {
            Some(dc) => {
                self.node(dc);
                let p = props(self.g, dc);
                let msg = if upn {
                    let v = prop_text(&p, "certificatemappingmethodsraw").unwrap_or_default();
                    format!("DC {} maps certificates by UPN (CertificateMappingMethods = {v}).", self.name(dc))
                } else {
                    let v = prop_text(&p, "strongcertificatebindingenforcementraw").unwrap_or_default();
                    format!("DC {} does not enforce strong certificate binding (StrongCertificateBindingEnforcement = {v}).", self.name(dc))
                };
                self.note(msg);
            }
            None => {
                let what = if upn { "with UPN certificate mapping" } else { "without strong certificate binding" };
                let msg = format!("a DC of {}'s forest {what}", self.name(d));
                self.missing(msg);
            }
        }
    }

    fn adcs(&mut self, s: u32, d: u32, kind: u16, name: &str) {
        let whys = adcs::witnesses(self.g, (s, d, kind));
        let Some(&why) = whys.iter().find(|w| **w != Why::Structural) else {
            return self.missing("the ADCS rule match (re-ingest may be needed)");
        };
        if whys.len() > 1 {
            let msg = format!("{} rule matches produce this edge; the first is shown.", whys.len());
            self.note(msg);
        }
        match why {
            Why::Structural => unreachable!(),
            Why::Golden { e, host } => {
                self.require_edge(host, e, "HostsCAService");
                self.ca_chain(e, d);
                let msg = format!(
                    "{} hosts {}, which is trusted to issue logon certificates for {}: control of the host gives the CA's private key, enough to forge a certificate for any principal.",
                    self.name(host),
                    self.name(e),
                    self.name(d)
                );
                self.note(msg);
            }
            Why::Enroll { e, t } => {
                self.template_enroll(s, t);
                self.ca_enroll(s, e);
                self.require_edge(t, e, "PublishedTo");
                let dom = if name == "ADCSESC13" { self.chained_domain(e) } else { Some(d) };
                match dom {
                    Some(dom) => self.ca_chain(e, dom),
                    None => {
                        let msg = format!("a domain {} is trusted for", self.name(e));
                        self.missing(msg);
                    }
                }
                match name {
                    "ADCSESC1" => self.template_facts(
                        t,
                        &["enrolleesuppliessubject", "requiresmanagerapproval", "authenticationenabled", "schemaversion", "authorizedsignatures"],
                    ),
                    "ADCSESC6a" => {
                        self.ca_san_fact(e);
                        self.template_facts(t, &["nosecurityextension", "authenticationenabled", "requiresmanagerapproval"]);
                    }
                    "ADCSESC6b" => {
                        self.ca_san_fact(e);
                        self.template_facts(t, &["schannelauthenticationenabled", "requiresmanagerapproval"]);
                        self.dc_fact(d, true);
                    }
                    "ADCSESC13" => {
                        let ip = self.targets(t, "ExtendedByPolicy").into_iter().find(|&ip| self.targets(ip, "OIDGroupLink").contains(&d));
                        match ip {
                            Some(ip) => {
                                self.edge_if(t, ip, "ExtendedByPolicy");
                                self.edge_if(ip, d, "OIDGroupLink");
                                let msg = format!("Certificates from {} carry an issuance policy linked to {}: logging on with one grants the group's rights.", self.name(t), self.name(d));
                                self.note(msg);
                            }
                            None => {
                                let msg = format!("an issuance policy of {} linked to {}", self.name(t), self.name(d));
                                self.missing(msg);
                            }
                        }
                        self.template_facts(t, &["requiresmanagerapproval", "authenticationenabled"]);
                    }
                    _ => {}
                }
            }
            Why::Esc4 { e, t, variant } => {
                self.ca_enroll(s, e);
                let rights: &[&[&str]] = match variant {
                    0 => &[&["Owns", "WriteDacl", "WriteOwner", "GenericAll"]],
                    1 => &[&["GenericWrite"], &["Enroll", "AllExtendedRights"]],
                    2 => &[&["Enroll", "AllExtendedRights"], &["WritePKINameFlag"], &["WritePKIEnrollmentFlag"]],
                    3 => &[&["Enroll", "AllExtendedRights"], &["WritePKIEnrollmentFlag"]],
                    _ => &[&["Enroll", "AllExtendedRights"], &["WritePKINameFlag"]],
                };
                for r in rights {
                    self.holds(s, t, r);
                }
                self.require_edge(t, e, "PublishedTo");
                self.ca_chain(e, d);
                let msg = format!("Write access to {} lets the source make it vulnerable to ESC1 and enroll.", self.name(t));
                self.note(msg);
            }
            Why::Victim { e, t, victim } => {
                let rights = ["GenericAll", "GenericWrite", "Owns", "WriteOwner", "WriteDacl", "WritePublicInformation"];
                if !rights.iter().any(|r| self.edge_if(s, victim, r)) {
                    let msg = format!("{} controlling {}", self.name(s), self.name(victim));
                    self.missing(msg);
                }
                self.template_enroll(victim, t);
                self.ca_enroll(victim, e);
                self.require_edge(t, e, "PublishedTo");
                self.ca_chain(e, d);
                self.template_facts(
                    t,
                    &["nosecurityextension", "schannelauthenticationenabled", "subjectaltrequireupn", "subjectaltrequiredns", "enrolleesuppliessubject"],
                );
                self.dc_fact(d, name.starts_with("ADCSESC10"));
                let msg = format!(
                    "The source rewrites {}'s UPN or dNSHostName to impersonate a privileged account, enrolls as it, then restores the attribute.",
                    self.name(victim)
                );
                self.note(msg);
            }
            Why::Esc3 { e, ct1, ct2, eca1, agents } => {
                self.template_enroll(s, ct1);
                self.template_enroll(s, ct2);
                self.ca_enroll(s, eca1);
                self.ca_enroll(s, e);
                if agents {
                    self.holds(s, ct2, &["DelegatedEnrollmentAgent"]);
                }
                self.require_edge(ct1, ct2, "EnrollOnBehalfOf");
                self.require_edge(ct1, eca1, "PublishedTo");
                self.require_edge(ct2, e, "PublishedTo");
                self.ca_chain(e, d);
                if eca1 != e {
                    self.ca_chain(eca1, d);
                }
                let msg = format!(
                    "An enrollment agent certificate from {} lets the source request {} on behalf of any user.",
                    self.name(ct1),
                    self.name(ct2)
                );
                self.note(msg);
            }
        }
    }

    // --------------------------------------------------------- Entra rules

    /// The tenant containing `x`.
    fn tenant_of(&self, x: u32) -> Option<u32> {
        self.sources(x, "AZContains").into_iter().find(|&t| self.g.kind(t) == NodeKind::AzTenant)
    }

    /// Template id of a role: `roleDefinitionId` for scoped roles, else the template.
    fn role_tpl(&self, r: u32) -> String {
        if !self.targets(r, "AZScopedTo").is_empty() {
            if let Some(v) = prop_text(&props(self.g, r), "roleDefinitionId") {
                return v.to_ascii_uppercase();
            }
        }
        azure::role_template(self.g, r)
    }
    fn role_name(&self, r: u32) -> String {
        role::name(&self.role_tpl(r)).map(str::to_string).unwrap_or_else(|| self.name(r))
    }

    /// Where a role applies to `x`: scoped to it, or the tenant containing both.
    fn role_scope(&mut self, r: u32, x: u32) {
        if x == r || self.edge_if(r, x, "AZScopedTo") {
            return;
        }
        let (tr, tx) = (self.tenant_of(r), self.tenant_of(x));
        match (tr, tx) {
            (Some(a), Some(b)) if a == b => {
                self.edge_if(a, r, "AZContains");
                if a != x {
                    self.edge_if(a, x, "AZContains");
                }
            }
            _ if self.g.kind(x) == NodeKind::AzTenant && tr == Some(x) => {
                self.edge_if(x, r, "AZContains");
            }
            _ => {
                let msg = format!("{} and {} in the same tenant", self.name(r), self.name(x));
                self.missing(msg);
            }
        }
    }

    /// `h -AZHasRole-> r`, or `h -AZMemberOf-> group -AZHasRole-> r` through a
    /// role-assignable group, for a role with one of `tpls` that applies to `x`.
    fn role_holder(&mut self, h: u32, x: u32, tpls: &[&str]) -> Option<u32> {
        let g = self.g;
        let applies = |b: &Self, r: u32| {
            tpls.contains(&b.role_tpl(r).as_str())
                && (x == r || b.targets(r, "AZScopedTo").contains(&x) || b.tenant_of(r).is_some_and(|t| t == x || b.tenant_of(x) == Some(t)))
        };
        for r in self.targets(h, "AZHasRole") {
            if applies(self, r) {
                self.edge_if(h, r, "AZHasRole");
                return Some(r);
            }
        }
        for gr in self.targets(h, "AZMemberOf") {
            let assignable = prop_text(&props(g, gr), "isAssignableToRole").as_deref() == Some("true");
            if !assignable {
                continue;
            }
            for r in self.targets(gr, "AZHasRole") {
                if applies(self, r) {
                    self.edge_if(h, gr, "AZMemberOf");
                    self.edge_if(gr, r, "AZHasRole");
                    let msg = format!("{} is role-assignable, so its members hold its roles.", self.name(gr));
                    self.note(msg);
                    return Some(r);
                }
            }
        }
        None
    }

    fn azure_role(&mut self, s: u32, d: u32, kind: &str) {
        use role::*;
        let g = self.g;
        if g.kind(s) == NodeKind::AzRole {
            // Role → object edges: tenant-wide or scoped role assignments.
            self.role_scope(s, d);
            let tpl = self.role_tpl(s);
            let rn = self.role_name(s);
            let msg = match kind {
                "AZResetPassword" if RESET_ANY.contains(&tpl.as_str()) => format!("{rn} can reset the password of any user."),
                "AZResetPassword" if tpl == DIRECTORY_SYNC => {
                    format!("{rn}: the sync API can set the password hash of any synced user ({} is synced from AD).", self.name(d))
                }
                "AZResetPassword" => format!(
                    "{rn} can reset passwords of users that hold no administrator role outside the set it may manage and are not in a role-assignable group; {} qualifies.",
                    self.name(d)
                ),
                "AZAddSecret" => format!("{rn} can add credentials to any application or service principal."),
                "AZAddOwner" => format!("{rn} can add owners to any application or service principal."),
                _ => format!("{rn} grants {kind} on {}.", self.name(d)),
            };
            self.note(msg);
            return;
        }
        let tpls: Vec<&str> = match kind {
            "AZGlobalAdmin" => vec![GLOBAL_ADMIN],
            "AZPrivilegedRoleAdmin" => vec![PRIV_ROLE_ADMIN],
            "AZPrivilegedAuthAdmin" => vec![PRIV_AUTH_ADMIN],
            "AZExecuteCommand" => vec![INTUNE_ADMIN],
            "AZAddMembers" => ADD_MEMBERS_ANY.iter().chain(ADD_MEMBERS_NON_ASSIGNABLE).copied().collect(),
            "AZAddSecret" => ADD_SECRET.to_vec(),
            "AZAddOwner" => ADD_OWNER.to_vec(),
            "AZResetPassword" => vec![], // only emitted from roles
            _ => vec![],
        };
        match self.role_holder(s, d, &tpls) {
            Some(r) => {
                self.role_scope(r, d);
                let rn = self.role_name(r);
                let msg = match kind {
                    "AZAddMembers" if ADD_MEMBERS_NON_ASSIGNABLE.contains(&self.role_tpl(r).as_str()) => {
                        format!("{rn} can add members to groups that are not role-assignable; {} is not.", self.name(d))
                    }
                    "AZExecuteCommand" => format!("{rn} can run scripts on Intune-managed Windows devices such as {}.", self.name(d)),
                    _ => format!("{} holds {rn}.", self.name(s)),
                };
                self.note(msg);
            }
            None => {
                let msg = format!("a role of {} granting {kind} on {}", self.name(s), self.name(d));
                self.missing(msg);
            }
        }
    }

    fn ms_graph(&mut self, s: u32, d: u32, kind: &str) {
        let perms: Vec<&str> = azure::MG_POSTS.iter().filter(|(_, posts)| posts.contains(&kind)).map(|(p, _)| *p).collect();
        let mut found = None;
        for p in &perms {
            if let Some(res) = self.targets(s, p).into_iter().next() {
                self.edge_if(s, res, p);
                found = Some(*p);
                break;
            }
        }
        match found {
            Some(p) => {
                if let Some(t) = self.tenant_of(d).or_else(|| (self.g.kind(d) == NodeKind::AzTenant).then_some(d)) {
                    if t != d {
                        self.edge_if(t, d, "AZContains");
                    }
                }
                let perm = p.trim_start_matches("AZMG").replace('_', ".");
                let msg = format!("{} holds the Microsoft Graph application permission {perm}.", self.name(s));
                self.note(msg);
            }
            None => {
                let msg = format!("a Microsoft Graph permission ({}) held by {}", perms.join(", "), self.name(s));
                self.missing(msg);
            }
        }
    }

    // -------------------------------------------------------- hybrid rules

    fn synced(&mut self, s: u32, d: u32, kind: &str) {
        let g = self.g;
        let (ad, az) = if matches!(g.kind(s), NodeKind::AzUser | NodeKind::AzGroup) { (d, s) } else { (s, d) };
        let reverse = match kind {
            "SyncedToEntraUser" => "SyncedToADUser",
            "SyncedToADUser" => "SyncedToEntraUser",
            "SyncedToEntraGroup" => "SyncedToADGroup",
            _ => "SyncedToEntraGroup",
        };
        self.edge_if(d, s, reverse);
        let p = props(g, az);
        let sid = prop_text(&p, "onPremisesSecurityIdentifier");
        let msg = match sid {
            Some(sid) if sid.eq_ignore_ascii_case(g.oid(ad)) => {
                format!("{} is synced from AD: its onPremisesSecurityIdentifier ({sid}) is {}'s SID.", self.name(az), self.name(ad))
            }
            _ => match prop_text(&p, "onPremisesImmutableId") {
                Some(imm) => format!("{} is synced from AD: its onPremisesImmutableId ({imm}) decodes to {}'s objectGUID.", self.name(az), self.name(ad)),
                None => {
                    self.missing("the on-premises SID or immutable id linking the two accounts");
                    return;
                }
            },
        };
        self.note(msg);
        let how = match kind {
            "SyncedToEntraUser" => "Password hash sync / pass-through authentication: the AD password signs in to the cloud account.",
            "SyncedToADUser" => "Password writeback: a cloud password reset sets the AD password.",
            "SyncedToEntraGroup" => "Members of the AD group become members of the cloud group.",
            _ => "Membership of a synced group is mastered on-premises (not traversable).",
        };
        self.note(how);
    }

    fn connect_credentials(&mut self, c: u32, acct: u32) {
        let p = props(self.g, acct);
        let desc = prop_text(&p, "description").unwrap_or_default();
        let msg = if desc.is_empty() {
            format!("{} is an Entra Connect sync account; its name points to {} as the sync server.", self.name(acct), self.name(c))
        } else {
            format!("{} is an Entra Connect sync account (description: \"{desc}\"), whose credentials {} stores.", self.name(acct), self.name(c))
        };
        self.note(msg);
        self.note("Local administrators of the sync server can extract the sync accounts' credentials.");
    }

    fn seamless_sso(&mut self, c: u32, u: u32) {
        let g = self.g;
        let ad_user = self.targets(u, "SyncedToADUser").into_iter().next();
        if let Some(a) = ad_user {
            self.edge_if(u, a, "SyncedToADUser");
        }
        let sid = prop_text(&props(g, u), "onPremisesSecurityIdentifier").unwrap_or_default();
        let dom = domain_of(g, c);
        if let Some(d) = dom {
            self.node(d);
        }
        let dn = dom.map(|d| self.name(d)).unwrap_or_else(|| "its domain".into());
        let msg = format!(
            "{} is the Seamless SSO account of {dn}. Its Kerberos key forges a service ticket for any user of the domain, exchanged at Entra ID for a sign-in as the synced cloud user {} (on-premises SID {sid}).",
            self.name(c),
            self.name(u)
        );
        self.note(msg);
    }
}
