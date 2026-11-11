//! End-to-end build: ingest → CSR build → post-processing passes that need
//! the built graph (ADCS ESC edges, Azure role edges, hybrid identity links).
//! Shared by the CLI and the server so both produce identical graphs.

use crate::{ingest_with_progress, IngestOptions, IngestReport, Progress};
use anyhow::Result;
use ch_store::{BuildStats, Graph};
use serde::Serialize;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Default, Clone, Serialize)]
pub struct PostReport {
    /// Derived edges added per pass, e.g. `("adcs", 1234)`.
    pub passes: Vec<(String, u64)>,
    /// Nodes newly tagged Tier Zero by post-processing (hybrid rules).
    pub tier0_added: u64,
    pub secs: f64,
}

pub struct Built {
    pub graph: Graph,
    pub ingest: IngestReport,
    pub build: BuildStats,
    pub post: PostReport,
}

/// The `ingest` object stored in a graph's `meta.json`: merge policy, merge
/// counters and the source manifest.
pub fn ingest_meta(r: &IngestReport) -> serde_json::Value {
    serde_json::json!({
        "merge_policy": r.merge_policy,
        "superseded_objects": r.superseded_objects,
        "superseded_edges": r.superseded_edges,
        "sources": r.sources,
    })
}

pub fn build_graph(inputs: &[PathBuf], opts: &IngestOptions) -> Result<Built> {
    build_graph_with_progress(inputs, opts, &|_, _| {})
}

/// [`build_graph`] reporting progress up to ~85% (`building`, `post-processing`
/// after the ingest phases); callers add their own `writing` / `loading`.
pub fn build_graph_with_progress(inputs: &[PathBuf], opts: &IngestOptions, progress: Progress) -> Result<Built> {
    let (parts, ingest_report) = ingest_with_progress(inputs, opts, progress)?;
    progress("building", 62);
    let (graph, build) = Graph::build(parts)?;
    progress("post-processing", 75);
    let t = Instant::now();
    let mut post = PostReport::default();
    let mut ingest_report = ingest_report;
    let mut extra = Vec::new();
    for (name, pass) in crate::postprocess::PASSES {
        let edges = pass(&graph);
        if *name == "repl" {
            ingest_report.dcsync_edges = edges.iter().filter(|e| e.kind == ch_model::ek::DCSYNC).count() as u64;
        }
        post.passes.push((name.to_string(), edges.len() as u64));
        extra.extend(edges);
    }
    let mut graph = graph.with_extra_edges(extra)?;
    graph.set_ingest_meta(ingest_meta(&ingest_report));
    for id in crate::postprocess::tier0_nodes(&graph) {
        if !graph.has_flag(id, ch_model::flags::TIER0) {
            graph.set_flag(id, ch_model::flags::TIER0, true);
            post.tier0_added += 1;
        }
    }
    post.secs = t.elapsed().as_secs_f64();
    Ok(Built { graph, ingest: ingest_report, build, post })
}
