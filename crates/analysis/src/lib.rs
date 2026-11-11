//! Enterprise-grade analysis on top of the CopperHound engine:
//!
//! * [`findings`] — a catalog of attack-path risk findings with severity,
//!   remediation and MITRE ATT&CK mapping, each quantified by how much Tier
//!   Zero exposure fixing it would remove.
//! * [`simulate`] — what-if exposure for arbitrary edge / kind / node
//!   removals, and a greedy remediation planner.
//! * [`posture`] — snapshot summaries and finding diffs between snapshots.

pub mod findings;
pub mod posture;
pub mod report;
pub mod simulate;

use ahash::AHashSet;
use ch_store::Graph;

/// An edge as `(src, dst, kind)`.
pub type EdgeKey = (u32, u32, u16);

/// Stable, human-readable key for an edge across snapshots (object ids, not
/// node ids, which change on every build).
pub fn edge_key(g: &Graph, (s, d, k): EdgeKey) -> String {
    format!("{}|{}|{}", g.oid(s), g.edge_kind_name(k), g.oid(d))
}

pub fn edge_label(g: &Graph, (s, d, k): EdgeKey) -> String {
    format!("{} -[{}]-> {}", g.name(s), g.edge_kind_name(k), g.name(d))
}

pub(crate) use ch_engine::is_principal;

/// Edges, edge kinds and nodes removed in a what-if scenario.
#[derive(Default, Clone)]
pub struct Removal {
    pub edges: AHashSet<EdgeKey>,
    pub kinds: AHashSet<u16>,
    pub nodes: AHashSet<u32>,
}

impl Removal {
    #[inline]
    pub fn blocks(&self, s: u32, d: u32, k: u16) -> bool {
        (!self.kinds.is_empty() && self.kinds.contains(&k))
            || (!self.nodes.is_empty() && (self.nodes.contains(&s) || self.nodes.contains(&d)))
            || (!self.edges.is_empty() && self.edges.contains(&(s, d, k)))
    }
}
