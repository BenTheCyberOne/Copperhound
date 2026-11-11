//! Post-processing passes over the built graph. Each pass returns derived
//! edges; the pipeline merges them in a single CSR rebuild.

mod ad;
pub mod explain;
mod adcs;
mod azure;
mod hybrid;
mod repl;

use ahash::AHashMap;
use parking_lot::Mutex;
use ch_model::{ek, NodeKind};
use ch_store::{Edge, Graph};
use std::sync::Arc;

pub type Pass = fn(&Graph) -> Vec<Edge>;

/// Registered passes, run in order.
pub const PASSES: &[(&str, Pass)] = &[
    ("repl", repl::pass),
    ("ad", ad::pass),
    ("adcs", adcs::pass),
    ("azure", azure::pass),
    ("hybrid", hybrid::pass),
];

/// Nodes that post-processing tags Tier Zero once derived edges exist:
/// Entra Connect sync accounts (both sides) and their server, and the Seamless
/// SSO computer account. See [`hybrid::tier0_nodes`].
pub fn tier0_nodes(g: &Graph) -> Vec<u32> {
    hybrid::tier0_nodes(g)
}

/// Forests: connected components of domains over `SameForestTrust` (either
/// direction — intra-forest trusts are two-way and transitive).
pub(crate) struct Forests {
    /// Domain → index into `sets`. Domains without intra-forest trusts are absent.
    of: AHashMap<u32, usize>,
    sets: Vec<Vec<u32>>,
}

impl Forests {
    pub fn new(g: &Graph) -> Self {
        let mut of: AHashMap<u32, usize> = AHashMap::new();
        let mut sets: Vec<Vec<u32>> = Vec::new();
        let Some(sft) = g.edge_kind_id("SameForestTrust") else { return Forests { of, sets } };
        for d in (0..g.node_count() as u32).filter(|&i| g.kind(i) == NodeKind::Domain) {
            if of.contains_key(&d) {
                continue;
            }
            let idx = sets.len();
            let mut set = vec![d];
            of.insert(d, idx);
            let mut i = 0;
            while i < set.len() {
                let x = set[i];
                i += 1;
                let (o, ok) = g.out_edges(x);
                let (n, nk) = g.in_edges(x);
                for (&y, &k) in o.iter().zip(ok).chain(n.iter().zip(nk)) {
                    if k == sft && g.kind(y) == NodeKind::Domain && !of.contains_key(&y) {
                        of.insert(y, idx);
                        set.push(y);
                    }
                }
            }
            if set.len() == 1 {
                of.remove(&d);
            } else {
                sets.push(set);
            }
        }
        Forests { of, sets }
    }

    /// All domains in `d`'s forest, `d` included (just `[d]` when unknown).
    pub fn forest(&self, d: u32) -> Vec<u32> {
        match self.of.get(&d) {
            Some(&i) => self.sets[i].clone(),
            None => vec![d],
        }
    }

    pub fn all(&self) -> &[Vec<u32>] {
        &self.sets
    }
}

/// Dense bitmap over node ids.
pub(crate) struct Bits(Vec<u64>);

impl Bits {
    pub fn new(n: usize) -> Self {
        Bits(vec![0; n.div_ceil(64)])
    }
    #[inline]
    pub fn set(&mut self, i: u32) {
        self.0[i as usize >> 6] |= 1 << (i & 63);
    }
    #[inline]
    pub fn get(&self, i: u32) -> bool {
        self.0[i as usize >> 6] & (1 << (i & 63)) != 0
    }
    pub fn and(&mut self, o: &Bits) {
        for (a, b) in self.0.iter_mut().zip(&o.0) {
            *a &= b;
        }
    }
}

/// Cached transitive group membership over `MemberOf` (AD) and `AZMemberOf`.
pub(crate) struct Members<'g> {
    g: &'g Graph,
    kinds: [u16; 2],
    cache: Mutex<AHashMap<u32, Arc<Vec<u32>>>>,
}

impl<'g> Members<'g> {
    pub fn new(g: &'g Graph) -> Self {
        Members { g, kinds: [ek::MEMBER_OF, ch_model::ek_of("AZMemberOf")], cache: Mutex::new(AHashMap::new()) }
    }

    pub fn is_group(&self, id: u32) -> bool {
        matches!(self.g.kind(id), NodeKind::Group | NodeKind::AzGroup)
    }

    /// All transitive members of `id` (empty for non-groups).
    pub fn members(&self, id: u32) -> Arc<Vec<u32>> {
        if let Some(v) = self.cache.lock().get(&id) {
            return v.clone();
        }
        let mut seen = ahash::AHashSet::new();
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(x) = stack.pop() {
            let (ss, ks) = self.g.in_edges(x);
            for (&s, k) in ss.iter().zip(ks) {
                if self.kinds.contains(k) && s != id && seen.insert(s) {
                    out.push(s);
                    stack.push(s);
                }
            }
        }
        let v = Arc::new(out);
        self.cache.lock().insert(id, v.clone());
        v
    }
}
