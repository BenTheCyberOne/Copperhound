//! Posture snapshots and finding diffs between snapshots.

use crate::findings::FindingResult;
use ch_store::Graph;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-snapshot summary (persisted in posture history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub created_at: String,
    pub nodes: u64,
    pub edges: u64,
    pub tier0: u64,
    pub exposed_principals: u64,
    pub total_principals: u64,
    pub exposure_percent: f64,
    /// Finding counts by severity.
    pub findings: BTreeMap<String, u64>,
    /// Item count per finding id.
    pub finding_counts: BTreeMap<String, u64>,
}

/// Finding items per snapshot, for diffs: finding id → (key → label).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotItems {
    pub findings: BTreeMap<String, BTreeMap<String, String>>,
}

/// Items kept per finding for diffing (keeps snapshot files bounded).
pub const MAX_ITEMS_PER_FINDING: usize = 20_000;

pub fn snapshot_items(g: &Graph, results: &[FindingResult]) -> SnapshotItems {
    let mut out = SnapshotItems::default();
    for r in results {
        let map: BTreeMap<String, String> = r.item_labels(g).into_iter().take(MAX_ITEMS_PER_FINDING).collect();
        out.findings.insert(r.def.id.to_string(), map);
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemLabel {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDiff {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub added: usize,
    pub removed: usize,
    pub added_items: Vec<ItemLabel>,
    pub removed_items: Vec<ItemLabel>,
}

/// Findings whose items changed between `from` and `to` (up to `sample` labels per side).
pub fn diff(from: &SnapshotItems, to: &SnapshotItems, sample: usize) -> Vec<FindingDiff> {
    let mut ids: Vec<&String> = from.findings.keys().chain(to.findings.keys()).collect();
    ids.sort();
    ids.dedup();
    let empty = BTreeMap::new();
    let mut out = Vec::new();
    for id in ids {
        let a = from.findings.get(id).unwrap_or(&empty);
        let b = to.findings.get(id).unwrap_or(&empty);
        let added: Vec<(&String, &String)> = b.iter().filter(|(k, _)| !a.contains_key(*k)).collect();
        let removed: Vec<(&String, &String)> = a.iter().filter(|(k, _)| !b.contains_key(*k)).collect();
        if added.is_empty() && removed.is_empty() {
            continue;
        }
        let def = crate::findings::CATALOG.iter().find(|d| d.id == id.as_str());
        let to_labels = |v: &[(&String, &String)]| {
            v.iter().take(sample).map(|(k, l)| ItemLabel { key: (*k).clone(), label: (*l).clone() }).collect()
        };
        out.push(FindingDiff {
            id: id.clone(),
            title: def.map(|d| d.title.to_string()).unwrap_or_else(|| id.clone()),
            severity: def
                .map(|d| serde_json::to_value(d.severity).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default())
                .unwrap_or_default(),
            added: added.len(),
            removed: removed.len(),
            added_items: to_labels(&added),
            removed_items: to_labels(&removed),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_reports_added_and_removed() {
        let mut a = SnapshotItems::default();
        let mut b = SnapshotItems::default();
        a.findings.insert("dcsync-non-tier0".into(), [("k1".into(), "A".into()), ("k2".into(), "B".into())].into());
        b.findings.insert("dcsync-non-tier0".into(), [("k2".into(), "B".into()), ("k3".into(), "C".into())].into());
        b.findings.insert("asrep-roastable".into(), [("u1".into(), "U1".into())].into());
        let d = diff(&a, &b, 10);
        assert_eq!(d.len(), 2);
        let dc = d.iter().find(|x| x.id == "dcsync-non-tier0").unwrap();
        assert_eq!((dc.added, dc.removed), (1, 1));
        assert_eq!(dc.severity, "critical");
        assert_eq!(dc.added_items[0].label, "C");
    }
}
