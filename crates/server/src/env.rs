//! Environments: AD domains and Entra tenants, and which one each object
//! belongs to, for scoping findings and reports (`?env=<objectid>`).
//!
//! An object belongs to the domain of its SID (`S-1-5-21-…-RID`), else of its
//! `domainsid` property; to the tenant that `AZContains` it, else of its
//! `tenantId` property. Domains and tenants belong to themselves. A finding
//! item belongs to the environment of its target (edge items) or of the
//! object itself (node items); an edge whose target has none uses its source.

use crate::state::Loaded;
use parking_lot::Mutex;
use ch_analysis::findings::{FindingResult, Items};
use ch_model::NodeKind;
use ch_store::Graph;
use serde::Serialize;
use std::sync::Arc;

pub const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Serialize)]
pub struct EnvInfo {
    /// Object id of the domain / tenant (stable across snapshots).
    pub id: String,
    pub name: String,
    /// `ad` or `tenant`.
    pub kind: &'static str,
    pub objects: u64,
    #[serde(skip)]
    pub node: u32,
}

pub struct Envs {
    /// Node → index into `list`, or [`NONE`].
    pub of: Vec<u32>,
    pub list: Vec<EnvInfo>,
}

impl Envs {
    pub fn index(&self, objectid: &str) -> Option<u32> {
        self.list.iter().position(|e| e.id.eq_ignore_ascii_case(objectid)).map(|i| i as u32)
    }
    pub fn env_of(&self, node: u32) -> u32 {
        self.of.get(node as usize).copied().unwrap_or(NONE)
    }
}

fn prop_str<'a>(props: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let i = props.find(&pat)? + pat.len();
    let rest = &props[i..];
    Some(&rest[..rest.find('"')?])
}

pub fn compute(g: &Graph) -> Envs {
    let n = g.node_count() as u32;
    let mut list: Vec<EnvInfo> = Vec::new();
    let mut idx_of_node: ahash::AHashMap<u32, u32> = ahash::AHashMap::new();
    for i in 0..n {
        let kind = match g.kind(i) {
            NodeKind::Domain => "ad",
            NodeKind::AzTenant => "tenant",
            _ => continue,
        };
        idx_of_node.insert(i, list.len() as u32);
        list.push(EnvInfo { id: g.oid(i).to_string(), name: g.name(i).to_string(), kind, objects: 0, node: i });
    }
    let mut of = vec![NONE; n as usize];
    for (&node, &ix) in &idx_of_node {
        of[node as usize] = ix;
    }
    // Tenant containment first (authoritative for Entra objects).
    if let Some(contains) = g.edge_kind_id("AZContains") {
        for e in list.iter().filter(|e| e.kind == "tenant") {
            let ix = idx_of_node[&e.node];
            let (ds, ks) = g.out_edges(e.node);
            for (&x, &k) in ds.iter().zip(ks) {
                if k == contains && of[x as usize] == NONE {
                    of[x as usize] = ix;
                }
            }
        }
    }
    let by_oid = |oid: &str| g.lookup(oid).and_then(|d| idx_of_node.get(&d).copied());
    for i in 0..n {
        if of[i as usize] != NONE {
            continue;
        }
        let oid = g.oid(i);
        let mut env = None;
        if oid.starts_with("S-1-5-21-") {
            env = oid.rsplit_once('-').and_then(|(p, _)| by_oid(p));
        }
        if env.is_none() {
            let p = g.props(i);
            env = prop_str(p, "domainsid").and_then(by_oid).or_else(|| prop_str(p, "tenantId").and_then(by_oid));
        }
        if let Some(e) = env {
            of[i as usize] = e;
        }
    }
    for &e in &of {
        if e != NONE {
            list[e as usize].objects += 1;
        }
    }
    Envs { of, list }
}

type Cache = Mutex<Option<(u64, Arc<Envs>)>>;

fn cache() -> &'static Cache {
    static C: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Environments of the loaded graph (computed once per generation).
pub fn of_loaded(l: &Loaded) -> Arc<Envs> {
    if let Some((g, e)) = cache().lock().as_ref() {
        if *g == l.generation {
            return e.clone();
        }
    }
    let e = Arc::new(compute(&l.graph));
    *cache().lock() = Some((l.generation, e.clone()));
    e
}

/// Findings restricted to items of environment `env`; findings left empty
/// are dropped. Exposure figures are graph-wide, so they are removed.
pub fn scope(findings: &[FindingResult], envs: &Envs, env: u32) -> Vec<FindingResult> {
    findings
        .iter()
        .filter_map(|f| {
            let items = match &f.items {
                Items::Edges(es) => Items::Edges(
                    es.iter()
                        .copied()
                        .filter(|&(s, d, _)| {
                            let e = envs.env_of(d);
                            (if e == NONE { envs.env_of(s) } else { e }) == env
                        })
                        .collect(),
                ),
                Items::Nodes(ns) => Items::Nodes(ns.iter().copied().filter(|&n| envs.env_of(n) == env).collect()),
            };
            let empty = match &items {
                Items::Edges(v) => v.is_empty(),
                Items::Nodes(v) => v.is_empty(),
            };
            (!empty).then_some(FindingResult { def: f.def, items, truncated: f.truncated, exposure: None })
        })
        .collect()
}
