//! ADCS post-processing: structural edges that need the whole graph and the
//! composite ESC edges. Semantics follow docs/research/adcs.md (BloodHound CE
//! behaviour, source-verified), with these deliberate differences:
//!
//! * `Owns`/`WriteOwner` are used as ingested (SharpHound emits them
//!   directly), so ESC4/9/10 owner paths appear on the first analysis.
//! * Forest-level DC checks (ESC6b/9/10) use the DCs of every domain in the
//!   target domain's forest (`SameForestTrust` component, see `ad.rs`); the
//!   enterprise-CA "same forest" scoping of ESC victims is not applied.

use super::{Bits, Forests, Members};
use ahash::{AHashMap, AHashSet};
use ch_model::{ek, ek_of, flags, NodeKind};
use ch_store::{Edge, Graph};
use serde_json::{Map, Value};

const OID_ANY_PURPOSE: &str = "2.5.29.37.0";
const OID_CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

type Props = Map<String, Value>;

fn props_of(g: &Graph, id: u32) -> Props {
    serde_json::from_str(g.props(id)).unwrap_or_default()
}
fn b(p: &Props, k: &str) -> Option<bool> {
    p.get(k).and_then(Value::as_bool)
}
fn n(p: &Props, k: &str) -> Option<f64> {
    p.get(k).and_then(Value::as_f64)
}
fn s(p: &Props, k: &str) -> Option<String> {
    p.get(k).and_then(Value::as_str).map(str::to_ascii_uppercase)
}
fn list(p: &Props, k: &str) -> Vec<String> {
    p.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_ascii_uppercase).collect())
        .unwrap_or_default()
}

/// `!(schemaversion > 1 && authorizedsignatures > 0)`; both must be present.
fn sig_ok(t: &Props) -> Option<bool> {
    Some(!(n(t, "schemaversion")? > 1.0 && n(t, "authorizedsignatures")? > 0.0))
}

fn schannel_auth(t: &Props) -> bool {
    b(t, "schannelauthenticationenabled").unwrap_or_else(|| {
        let ekus = list(t, "effectiveekus");
        ekus.is_empty() || ekus.iter().any(|e| e == OID_CLIENT_AUTH || e == OID_ANY_PURPOSE)
    })
}

struct Ctx<'g> {
    g: &'g Graph,
    m: Members<'g>,
    props: AHashMap<u32, Props>,
    special: AHashSet<u32>,
    k: AHashMap<&'static str, u16>,
    forests: Forests,
}

impl<'g> Ctx<'g> {
    fn kid(&self, name: &'static str) -> u16 {
        self.k[name]
    }
    fn p(&self, id: u32) -> &Props {
        static EMPTY: std::sync::OnceLock<Props> = std::sync::OnceLock::new();
        self.props.get(&id).unwrap_or_else(|| EMPTY.get_or_init(Props::new))
    }
    /// First-degree sources of `kinds` into `x`.
    fn sources(&self, x: u32, kinds: &[u16]) -> Vec<u32> {
        let (ss, ks) = self.g.in_edges(x);
        let mut v: Vec<u32> = ss.iter().zip(ks).filter(|(_, k)| kinds.contains(k)).map(|(&s, _)| s).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
    fn targets(&self, x: u32, kind: u16) -> Vec<u32> {
        let (ds, ks) = self.g.out_edges(x);
        ds.iter().zip(ks).filter(|(_, k)| **k == kind).map(|(&d, _)| d).collect()
    }
    fn template_enrollers(&self, t: u32) -> Vec<u32> {
        self.sources(t, &[self.kid("Enroll"), ek::GENERIC_ALL, self.kid("AllExtendedRights")])
    }
    fn ca_enrollers(&self, e: u32) -> Vec<u32> {
        self.sources(e, &[self.kid("Enroll")])
    }

    /// A set is "excluded" (satisfied by everyone) when it holds Authenticated
    /// Users / Everyone directly or transitively.
    fn excluded(&self, set: &[u32]) -> bool {
        set.iter().any(|&p| self.special.contains(&p) || self.m.members(p).iter().any(|x| self.special.contains(x)))
    }

    fn unrolled(&self, set: &[u32]) -> Bits {
        let mut bits = Bits::new(self.g.node_count());
        for &p in set {
            bits.set(p);
            for &m in self.m.members(p).iter() {
                bits.set(m);
            }
        }
        bits
    }

    /// Principals holding every right, reported at the highest group level
    /// (BloodHound's CalculateCrossProductNodeSets).
    fn cross_product(&self, sets: &[Vec<u32>]) -> Vec<u32> {
        let non: Vec<&Vec<u32>> = sets.iter().filter(|s| !self.excluded(s)).collect();
        if non.is_empty() {
            let mut all: Vec<u32> = sets.iter().flatten().copied().collect();
            all.sort_unstable();
            all.dedup();
            return all;
        }
        if non.len() == 1 {
            return non[0].clone();
        }
        let mut check = self.unrolled(non[1]);
        for s in &non[2..] {
            check.and(&self.unrolled(s));
        }
        let mut result: Vec<u32> = Vec::new();
        let mut candidates: AHashSet<u32> = AHashSet::new();
        for &p in non[0] {
            if check.get(p) {
                result.push(p);
            } else {
                candidates.extend(self.m.members(p).iter().copied());
            }
        }
        let mut groups: Vec<u32> = candidates.iter().copied().filter(|&c| self.m.is_group(c)).collect();
        groups.sort_by_key(|&g| (self.m.members(g).len(), g));
        for gid in groups {
            if !candidates.contains(&gid) {
                continue;
            }
            if check.get(gid) {
                result.push(gid);
                for m in self.m.members(gid).iter() {
                    candidates.remove(m);
                }
            }
            candidates.remove(&gid);
        }
        result.extend(candidates.into_iter().filter(|&c| !self.m.is_group(c) && check.get(c)));
        result.sort_unstable();
        result.dedup();
        result
    }

    /// Expand to non-group principals (ESC9/10 victims), no shortcutting.
    fn expand_no_groups(&self, set: &[u32]) -> AHashSet<u32> {
        let mut out = AHashSet::new();
        for &p in set {
            if self.m.is_group(p) {
                out.extend(self.m.members(p).iter().copied().filter(|&x| !self.m.is_group(x)));
            } else {
                out.insert(p);
            }
        }
        out
    }

    /// Set contains Authenticated Users / Everyone, or one of them is a direct member of a group in it.
    fn special_direct(&self, set: &[u32]) -> bool {
        let mo = ek::MEMBER_OF;
        set.iter().any(|p| self.special.contains(p))
            || self.special.iter().any(|&s| self.targets(s, mo).iter().any(|g| set.contains(g)))
    }

    fn victims(&self, te: &[u32], ce: &[u32]) -> Vec<u32> {
        let (st, sc) = (self.special_direct(te), self.special_direct(ce));
        let t = self.expand_no_groups(te);
        let c = self.expand_no_groups(ce);
        let mut v: Vec<u32> = if !st && !sc {
            t.intersection(&c).copied().collect()
        } else {
            let mut v = Vec::new();
            if st {
                v.extend(c.iter().copied());
            }
            if sc {
                v.extend(t.iter().copied());
            }
            v
        };
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Drop users unless gMSA/MSA when the template requires a DNS SAN
    /// (a missing property counts as "requires").
    fn dns_filter(&self, set: Vec<u32>, t: u32) -> Vec<u32> {
        let tp = self.p(t);
        let requires = !(b(tp, "subjectaltrequiredns") == Some(false) && b(tp, "subjectaltrequiredomaindns") == Some(false));
        if !requires {
            return set;
        }
        set.into_iter()
            .filter(|&x| {
                self.g.kind(x) != NodeKind::User || {
                    let p = props_of(self.g, x);
                    b(&p, "gmsa") == Some(true) || b(&p, "msa") == Some(true)
                }
            })
            .collect()
    }

    fn upn_mapping(&self, d: u32) -> bool {
        upn_mapping_dc(self.g, &self.forests, d).is_some()
    }
    fn weak_binding(&self, d: u32) -> bool {
        weak_binding_dc(self.g, &self.forests, d).is_some()
    }
}

/// DCs of every domain in `d`'s forest (BH CE: `SameForestTrust` closure).
fn dcs_of(g: &Graph, forests: &Forests, d: u32) -> Vec<u32> {
    forests
        .forest(d)
        .into_iter()
        .filter_map(|fd| g.lookup(&format!("{}-516", g.oid(fd))))
        .flat_map(|group| {
            let (ss, ks) = g.in_edges(group);
            ss.iter().zip(ks).filter(|(_, &k)| k == ek::MEMBER_OF).map(|(&s, _)| s).collect::<Vec<_>>()
        })
        .filter(|&c| g.kind(c) == NodeKind::Computer)
        .collect()
}

/// A DC of `d`'s forest whose certificate mapping methods include UPN mapping (ESC6b / ESC10).
pub(crate) fn upn_mapping_dc(g: &Graph, forests: &Forests, d: u32) -> Option<u32> {
    dcs_of(g, forests, d).into_iter().find(|&dc| {
        let p = props_of(g, dc);
        n(&p, "certificatemappingmethodsraw").is_some_and(|v| v != -1.0 && (v as i64) & 0x4 != 0)
    })
}

/// A DC of `d`'s forest without full strong certificate binding enforcement (ESC9).
pub(crate) fn weak_binding_dc(g: &Graph, forests: &Forests, d: u32) -> Option<u32> {
    dcs_of(g, forests, d).into_iter().find(|&dc| {
        let p = props_of(g, dc);
        n(&p, "strongcertificatebindingenforcementraw").is_some_and(|v| v == 0.0 || v == 1.0 || v == -1.0)
    })
}

/// Why a composite ADCS edge was emitted: the objects the rule matched. The
/// explanation in `explain.rs` turns this into the supporting edges.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Why {
    /// Built from certificate data, not composed from rights.
    Structural,
    /// GoldenCert: `host` runs the CA service of `e`.
    Golden { e: u32, host: u32 },
    /// Enrollment on template `t` at CA `e` (ESC1, ESC6a/b, ESC13).
    Enroll { e: u32, t: u32 },
    /// ESC4 rule `variant` (0..=4, in the order of the rule sets in `run`).
    Esc4 { e: u32, t: u32, variant: u8 },
    /// ESC9/ESC10: the source controls `victim`, which can enroll on `t` at `e`.
    Victim { e: u32, t: u32, victim: u32 },
    /// ESC3: agent template `ct1` (published by `eca1`) enrolls on behalf of `ct2` at `e`.
    Esc3 { e: u32, ct1: u32, ct2: u32, eca1: u32, agents: bool },
}

/// At most this many witnesses are kept per explained edge.
const MAX_WITNESSES: usize = 8;

pub fn pass(g: &Graph) -> Vec<Edge> {
    run(g, None).0
}

/// The rule matches that produced the edge `want` (empty when the pass does
/// not emit it).
pub(crate) fn witnesses(g: &Graph, want: (u32, u32, u16)) -> Vec<Why> {
    run(g, Some(want)).1
}

fn run(g: &Graph, want: Option<(u32, u32, u16)>) -> (Vec<Edge>, Vec<Why>) {
    let by_kind = |k: NodeKind| -> Vec<u32> { (0..g.node_count() as u32).filter(|&i| g.kind(i) == k).collect() };
    let ecas = by_kind(NodeKind::EnterpriseCa);
    if ecas.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let roots = by_kind(NodeKind::RootCa);
    let aias = by_kind(NodeKind::AiaCa);
    let stores = by_kind(NodeKind::NtAuthStore);
    let templates = by_kind(NodeKind::CertTemplate);
    let policies = by_kind(NodeKind::IssuancePolicy);

    let mut props = AHashMap::new();
    for &id in ecas.iter().chain(&roots).chain(&aias).chain(&stores).chain(&templates).chain(&policies) {
        props.insert(id, props_of(g, id));
    }
    let special: AHashSet<u32> = (0..g.node_count() as u32)
        .filter(|&i| g.kind(i) == NodeKind::Group && (g.oid(i).ends_with("S-1-5-11") || g.oid(i).ends_with("S-1-1-0")))
        .collect();
    let names: &[&'static str] = &[
        "Enroll", "AllExtendedRights", "PublishedTo", "HostsCAService", "RootCAFor", "NTAuthStoreFor", "OIDGroupLink",
        "DelegatedEnrollmentAgent", "Owns", "WriteDacl", "WriteOwner", "GenericWrite", "WritePKINameFlag",
        "WritePKIEnrollmentFlag", "WritePublicInformation",
    ];
    let k: AHashMap<&'static str, u16> = names.iter().map(|&nm| (nm, ek_of(nm))).collect();
    let cx = Ctx { g, m: Members::new(g), props, special, k, forests: Forests::new(g) };

    let mut out: AHashSet<(u32, u32, u16)> = AHashSet::new();
    let mut whys: Vec<Why> = Vec::new();
    let mut emit = |s: u32, d: u32, kind: &str, why: Why| {
        if s != d {
            let e = (s, d, ek_of(kind));
            if want == Some(e) && whys.len() < MAX_WITNESSES && !whys.contains(&why) {
                whys.push(why);
            }
            out.insert(e);
        }
    };

    // ---- structural edges (kept in memory too, for chain validation)
    let mut by_thumb: AHashMap<String, Vec<u32>> = AHashMap::new();
    for &id in ecas.iter().chain(&roots).chain(&aias) {
        if let Some(t) = s(cx.p(id), "certthumbprint").filter(|t| !t.is_empty()) {
            by_thumb.entry(t).or_default().push(id);
        }
    }
    let mut chain_next: AHashMap<u32, Vec<u32>> = AHashMap::new(); // IssuedSignedBy ∪ EnterpriseCAFor
    let mut ntauth: AHashMap<u32, Vec<u32>> = AHashMap::new(); // ECA → stores
    for &st in &stores {
        for t in list(cx.p(st), "certthumbprints") {
            for &e in by_thumb.get(&t).into_iter().flatten() {
                if g.kind(e) == NodeKind::EnterpriseCa {
                    emit(e, st, "TrustedForNTAuth", Why::Structural);
                    ntauth.entry(e).or_default().push(st);
                }
            }
        }
    }
    for &id in ecas.iter().chain(&roots).chain(&aias) {
        let chain = list(cx.p(id), "certchain");
        if chain.len() > 1 {
            for &parent in by_thumb.get(&chain[1]).into_iter().flatten() {
                if parent != id {
                    emit(id, parent, "IssuedSignedBy", Why::Structural);
                    chain_next.entry(id).or_default().push(parent);
                }
            }
        }
        if g.kind(id) == NodeKind::EnterpriseCa {
            if let Some(t) = s(cx.p(id), "certthumbprint") {
                for &other in by_thumb.get(&t).into_iter().flatten() {
                    if matches!(g.kind(other), NodeKind::RootCa | NodeKind::AiaCa) {
                        emit(id, other, "EnterpriseCAFor", Why::Structural);
                        chain_next.entry(id).or_default().push(other);
                    }
                }
            }
        }
    }
    let mut policy_by_oid: AHashMap<(String, String), Vec<u32>> = AHashMap::new();
    for &ip in &policies {
        if let (Some(oid), Some(dom)) = (s(cx.p(ip), "certtemplateoid"), s(cx.p(ip), "domainsid")) {
            if !dom.is_empty() {
                policy_by_oid.entry((oid, dom)).or_default().push(ip);
            }
        }
    }
    let mut extended_by: AHashMap<u32, Vec<u32>> = AHashMap::new();
    for &t in &templates {
        let Some(dom) = s(cx.p(t), "domainsid") else { continue };
        for oid in list(cx.p(t), "certificatepolicy") {
            for &ip in policy_by_oid.get(&(oid, dom.clone())).into_iter().flatten() {
                emit(t, ip, "ExtendedByPolicy", Why::Structural);
                extended_by.entry(t).or_default().push(ip);
            }
        }
    }

    // ---- per-ECA validity: qualifying host and chained domains
    let root_for = cx.kid("RootCAFor");
    let store_for = cx.kid("NTAuthStoreFor");
    let mut hosts: AHashMap<u32, Vec<u32>> = AHashMap::new();
    let mut domains: AHashMap<u32, Vec<u32>> = AHashMap::new();
    for &e in &ecas {
        let hs: Vec<u32> = cx
            .sources(e, &[cx.kid("HostsCAService")])
            .into_iter()
            .filter(|&c| g.kind(c) == NodeKind::Computer && g.has_flag(c, flags::ENABLED))
            .collect();
        if hs.is_empty() {
            continue;
        }
        // RootCA chain: e → (ECA|AIACA)* → RootCA -RootCAFor-> D
        let mut root_domains: AHashSet<u32> = AHashSet::new();
        let mut seen: AHashSet<u32> = AHashSet::from([e]);
        let mut stack = vec![e];
        while let Some(x) = stack.pop() {
            for &y in chain_next.get(&x).into_iter().flatten() {
                if !seen.insert(y) {
                    continue;
                }
                match g.kind(y) {
                    NodeKind::RootCa => root_domains.extend(cx.targets(y, root_for)),
                    NodeKind::EnterpriseCa | NodeKind::AiaCa => stack.push(y),
                    _ => {}
                }
            }
        }
        let auth_domains: AHashSet<u32> =
            ntauth.get(&e).into_iter().flatten().flat_map(|&st| cx.targets(st, store_for)).collect();
        let mut ds: Vec<u32> = root_domains.intersection(&auth_domains).copied().collect();
        ds.sort_unstable();
        if ds.is_empty() {
            continue;
        }
        hosts.insert(e, hs);
        domains.insert(e, ds);
    }
    let valid: Vec<u32> = ecas.iter().copied().filter(|e| domains.contains_key(e)).collect();
    let published = |e: u32| cx.sources(e, &[cx.kid("PublishedTo")]);

    // ---- EnrollOnBehalfOf (agent template → target template)
    let mut eobo: AHashMap<u32, Vec<u32>> = AHashMap::new(); // ct2 → [ct1]
    {
        let mut tmpl_domains: AHashMap<u32, AHashSet<u32>> = AHashMap::new();
        for &e in &valid {
            for t in published(e) {
                tmpl_domains.entry(t).or_default().extend(domains[&e].iter().copied());
            }
        }
        let ts: Vec<u32> = tmpl_domains.keys().copied().collect();
        for &ct1 in &ts {
            let p1 = cx.p(ct1);
            let ekus1 = list(p1, "effectiveekus");
            for &ct2 in &ts {
                if tmpl_domains[&ct1].is_disjoint(&tmpl_domains[&ct2]) {
                    continue;
                }
                let p2 = cx.p(ct2);
                let ok = match n(p2, "schemaversion") {
                    Some(v) if v >= 2.0 => {
                        !ekus1.iter().any(|e| e == OID_ANY_PURPOSE)
                            && ekus1.iter().any(|e| e == OID_CERT_REQUEST_AGENT)
                            && ct1 != ct2
                            && n(p2, "authorizedsignatures") == Some(1.0)
                            && list(p2, "applicationpolicies").iter().any(|e| e == OID_CERT_REQUEST_AGENT)
                    }
                    Some(1.0) => {
                        ekus1.is_empty() || ekus1.iter().any(|e| e == OID_CERT_REQUEST_AGENT || e == OID_ANY_PURPOSE)
                    }
                    _ => false,
                };
                if ok {
                    emit(ct1, ct2, "EnrollOnBehalfOf", Why::Structural);
                    eobo.entry(ct2).or_default().push(ct1);
                }
            }
        }
    }

    // ---- composite edges per ECA
    let rights = |names: &[&'static str]| -> Vec<u16> { names.iter().map(|&nm| cx.kid(nm)).collect() };
    let controllers = {
        let mut v = rights(&["Owns", "WriteDacl", "WriteOwner"]);
        v.push(ek::GENERIC_ALL);
        v
    };
    let generic_writers = rights(&["GenericWrite"]);
    let enroll_or_aer = rights(&["Enroll", "AllExtendedRights"]);
    let name_flag = rights(&["WritePKINameFlag"]);
    let enr_flag = rights(&["WritePKIEnrollmentFlag"]);
    let attacker_rights_a = {
        let mut v = rights(&["GenericWrite", "Owns", "WriteOwner", "WriteDacl", "WritePublicInformation"]);
        v.push(ek::GENERIC_ALL);
        v
    };
    let attacker_rights_b = {
        let mut v = rights(&["GenericWrite", "Owns", "WriteOwner", "WriteDacl"]);
        v.push(ek::GENERIC_ALL);
        v
    };

    for &e in &valid {
        let ds = &domains[&e];
        let ep = cx.p(e).clone();
        for &h in &hosts[&e] {
            for &d in ds {
                emit(h, d, "GoldenCert", Why::Golden { e, host: h });
            }
        }
        let ce = cx.ca_enrollers(e);
        let san_enabled = b(&ep, "isuserspecifiessanenabledcollected") == Some(true) && b(&ep, "isuserspecifiessanenabled") == Some(true);
        for t in published(e) {
            let tp = cx.p(t).clone();
            let te = cx.template_enrollers(t);
            let rma = b(&tp, "requiresmanagerapproval");
            let auth = b(&tp, "authenticationenabled");
            let ess = b(&tp, "enrolleesuppliessubject");
            let nse = b(&tp, "nosecurityextension");
            let sig = sig_ok(&tp);

            // ESC1
            if rma == Some(false) && auth == Some(true) && ess == Some(true) && sig == Some(true) {
                for p in cx.cross_product(&[te.clone(), ce.clone()]) {
                    for &d in ds {
                        emit(p, d, "ADCSESC1", Why::Enroll { e, t });
                    }
                }
            }
            // ESC4
            if ess.is_some() && rma.is_some() {
                // Rule sets; the index is `Why::Esc4::variant` (see `explain::esc4_requirements`).
                let mut r: Vec<(u32, u8)> = Vec::new();
                let mut add = |variant: u8, sets: Vec<Vec<u32>>| r.extend(cx.cross_product(&sets).into_iter().map(|p| (p, variant)));
                add(0, vec![ce.clone(), cx.sources(t, &controllers)]);
                if auth == Some(true) && sig == Some(true) {
                    add(1, vec![ce.clone(), cx.sources(t, &generic_writers), cx.sources(t, &enroll_or_aer)]);
                }
                let eoa = cx.sources(t, &enroll_or_aer);
                add(2, vec![ce.clone(), eoa.clone(), cx.sources(t, &name_flag), cx.sources(t, &enr_flag)]);
                if ess == Some(true) {
                    add(3, vec![ce.clone(), eoa.clone(), cx.sources(t, &enr_flag)]);
                }
                if rma == Some(false) {
                    add(4, vec![ce.clone(), eoa.clone(), cx.sources(t, &name_flag)]);
                }
                for (p, variant) in r {
                    for &d in ds {
                        emit(p, d, "ADCSESC4", Why::Esc4 { e, t, variant });
                    }
                }
            }
            // ESC6a / ESC6b
            if san_enabled && rma == Some(false) && sig == Some(true) {
                let six_a = nse == Some(true) && auth == Some(true);
                let six_b = schannel_auth(&tp);
                if six_a || six_b {
                    let r = cx.dns_filter(cx.cross_product(&[te.clone(), ce.clone()]), t);
                    for &p in &r {
                        for &d in ds {
                            if six_a {
                                emit(p, d, "ADCSESC6a", Why::Enroll { e, t });
                            }
                            if six_b && cx.upn_mapping(d) {
                                emit(p, d, "ADCSESC6b", Why::Enroll { e, t });
                            }
                        }
                    }
                }
            }
            // ESC9 / ESC10
            if !ce.is_empty() && !te.is_empty() && rma == Some(false) && ess == Some(false) && sig == Some(true) {
                let upn_or_spn = b(&tp, "subjectaltrequireupn") == Some(true) || b(&tp, "subjectaltrequirespn") == Some(true);
                let dns = b(&tp, "subjectaltrequiredns") == Some(true);
                let esc9 = auth == Some(true) && nse == Some(true);
                let esc10 = schannel_auth(&tp);
                for (variant_a, ok) in [(true, upn_or_spn), (false, dns)] {
                    if !ok || !(esc9 || esc10) {
                        continue;
                    }
                    let mut victims = cx.victims(&te, &ce);
                    if variant_a {
                        victims = cx.dns_filter(victims, t);
                    } else {
                        victims.retain(|&v| g.kind(v) == NodeKind::Computer);
                    }
                    let rs = if variant_a { &attacker_rights_a } else { &attacker_rights_b };
                    // Attacker → the victims it controls (the first is the witness).
                    let mut attackers: AHashMap<u32, Vec<u32>> = AHashMap::new();
                    for &v in &victims {
                        for a in cx.sources(v, rs) {
                            if matches!(g.kind(a), NodeKind::User | NodeKind::Group | NodeKind::Computer) {
                                attackers.entry(a).or_default().push(v);
                            }
                        }
                    }
                    for (&a, vs) in &attackers {
                        let why = Why::Victim { e, t, victim: vs[0] };
                        for &d in ds {
                            if esc9 && cx.weak_binding(d) {
                                emit(a, d, if variant_a { "ADCSESC9a" } else { "ADCSESC9b" }, why);
                            }
                            if esc10 && cx.upn_mapping(d) {
                                emit(a, d, if variant_a { "ADCSESC10a" } else { "ADCSESC10b" }, why);
                            }
                        }
                    }
                }
            }
            // ESC13 → linked group
            if rma == Some(false) && auth == Some(true) && sig == Some(true) {
                let groups: Vec<u32> = extended_by
                    .get(&t)
                    .into_iter()
                    .flatten()
                    .flat_map(|&ip| cx.targets(ip, cx.kid("OIDGroupLink")))
                    .filter(|&gr| g.kind(gr) == NodeKind::Group)
                    .collect();
                if !groups.is_empty() {
                    let r = cx.dns_filter(cx.cross_product(&[ce.clone(), te.clone()]), t);
                    for &p in &r {
                        for &gr in &groups {
                            emit(p, gr, "ADCSESC13", Why::Enroll { e, t });
                        }
                    }
                }
            }
        }

        // ESC3 (E as the target-template CA)
        let has_ear = b(&ep, "enrollmentagentrestrictionscollected") == Some(true) && b(&ep, "hasenrollmentagentrestrictions") == Some(true);
        for ct2 in published(e) {
            let p2 = cx.p(ct2).clone();
            if b(&p2, "authenticationenabled") != Some(true) || b(&p2, "requiresmanagerapproval") != Some(false) {
                continue;
            }
            for &ct1 in eobo.get(&ct2).into_iter().flatten() {
                let p1 = cx.p(ct1);
                let ok1 = b(p1, "requiresmanagerapproval") == Some(false)
                    && match n(p1, "schemaversion") {
                        Some(1.0) => true,
                        Some(v) if v > 1.0 => n(p1, "authorizedsignatures") == Some(0.0),
                        _ => false,
                    };
                if !ok1 {
                    continue;
                }
                let agents = if has_ear {
                    let a = cx.sources(ct2, &[cx.kid("DelegatedEnrollmentAgent")]);
                    if a.is_empty() {
                        continue;
                    }
                    Some(a)
                } else {
                    None
                };
                for eca1 in cx.targets(ct1, cx.kid("PublishedTo")) {
                    let Some(d1) = domains.get(&eca1) else { continue };
                    let mut sets = vec![cx.template_enrollers(ct1), cx.template_enrollers(ct2), cx.ca_enrollers(eca1), ce.clone()];
                    if let Some(a) = &agents {
                        sets.push(a.clone());
                    }
                    let r = cx.dns_filter(cx.cross_product(&sets), ct1);
                    for &d in ds.iter().filter(|d| d1.contains(d)) {
                        for &p in &r {
                            emit(p, d, "ADCSESC3", Why::Esc3 { e, ct1, ct2, eca1, agents: agents.is_some() });
                        }
                    }
                }
            }
        }
    }
    (out.into_iter().map(|(s, d, k)| Edge::new(s, d, k)).collect(), whys)
}
