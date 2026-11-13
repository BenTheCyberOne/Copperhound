//! Collected data in reports is untrusted: names and custom (OpenGraph) kind
//! names must not inject HTML or Markdown.

use ch_analysis::findings::evaluate;
use ch_analysis::report::{render_html, render_markdown, zone_sections, ReportInput};
use ch_analysis::simulate::{exposure_with, plan, PlanOptions};
use ch_analysis::Removal;
use ch_ingest::{build_graph, IngestOptions};
use ch_model::flags;
use serde_json::json;
use std::fs;

const EVIL_KIND: &str = "<img src=x onerror=alert(1)>";

#[test]
fn custom_kind_and_names_are_escaped() {
    let d = std::env::temp_dir().join(format!("ch-report-esc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let dom = "S-1-5-21-9-9-9";
    let da = format!("{dom}-512");
    // Three users reach Domain Admins only through one custom-kind node,
    // which makes it the plan's first choke object.
    let mut nodes = vec![
        json!({"id": "evil-1", "kinds": [EVIL_KIND], "properties": {"name": "EVIL ```\n<script>x</script> | cell"}}),
        json!({"id": da, "kinds": ["Group", "Tag_Tier_Zero"], "properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"}}),
    ];
    let mut edges = vec![json!({"kind": "GenericAll", "start": {"value": "evil-1"}, "end": {"value": da}})];
    for i in 0..3 {
        let u = format!("{dom}-{}", 1100 + i);
        nodes.push(json!({"id": u, "kinds": ["User"], "properties": {"name": format!("U{i}@CORP.LOCAL"), "enabled": true}}));
        edges.push(json!({"kind": "LinkedTo", "start": {"value": u}, "end": {"value": "evil-1"}}));
    }
    fs::write(d.join("og.json"), json!({"graph": {"nodes": nodes, "edges": edges}}).to_string()).unwrap();
    let g = build_graph(std::slice::from_ref(&d), &IngestOptions::default()).unwrap().graph;
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let rep = exposure_with(&g, &tier0, &Removal::default(), 10);
    let findings = evaluate(&g, &tier0, &ch_query::Cancel::never(), &|_, _| {});
    let p = plan(&g, &tier0, &PlanOptions { steps: 3, protect_target_membership: true, ..Default::default() }, &ch_query::Cancel::never());
    assert_eq!(g.kind_name(p.steps[0].node), EVIL_KIND, "the custom-kind node must be in the plan");
    // A zone with a hostile name, so the zone table and cross-zone plan show it.
    let zone_name = "<b onmouseover=x>Zone | x</b>";
    let zs = vec![("Tier Zero".to_string(), 1, tier0.clone()), (zone_name.to_string(), 2, tier0.clone())];
    let opts = PlanOptions { steps: 3, protect_target_membership: true, ..Default::default() };
    let (zones, cross) = zone_sections(&g, &zs, Some(&opts), &ch_query::Cancel::never());
    let cross = cross.expect("two weighted zones give a cross-zone plan");
    assert_eq!(cross.plan.steps[0].node, p.steps[0].node);
    assert_eq!(cross.plan.steps[0].score, 3 * p.steps[0].principals_cut);
    let input = ReportInput {
        title: "t",
        generated_at: "now",
        snapshot_id: "s",
        graph: &g,
        tier0: &rep,
        findings: &findings,
        posture: &[],
        plan: Some(&p),
        items_per_finding: 50,
        accepted: &[],
        zones: &zones,
        cross_zone_plan: Some(&cross),
    };
    let html = render_html(&input);
    assert!(!html.contains("<img"), "raw kind name in HTML");
    assert!(!html.contains("<script>"), "raw node name in HTML");
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(html.contains("Content-Security-Policy"));
    assert!(!html.contains("<b onmouseover"), "raw zone name in HTML");
    assert!(html.contains("&lt;b onmouseover=x&gt;Zone | x&lt;/b&gt; −"), "zone name in the cross-zone plan");
    assert!(html.contains("Zones</h2>") && html.contains("Across all zones, by weight"));
    let md = render_markdown(&input);
    assert!(!md.contains("<img") && !md.contains("<script>"), "raw HTML in Markdown");
    assert!(!md.contains("<b onmouseover") && md.contains(r"Zone \| x"), "zone name in Markdown");
    let _ = fs::remove_dir_all(&d);
}
