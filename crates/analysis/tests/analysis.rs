use ch_analysis::findings::{evaluate, Items};
use ch_analysis::simulate::{plan, simulate, PlanOptions};
use ch_analysis::Removal;
use ch_model::{ek, flags};
use ch_query::Cancel;

fn graph() -> ch_store::Graph {
    let dir = std::env::temp_dir().join(format!("ch-analysis-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 5_000, computers: 1_000, groups: 300, seed: 5 }, &dir).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    let _ = std::fs::remove_dir_all(&dir);
    g
}

#[test]
fn findings_simulation_and_plan() {
    let g = graph();
    let tier0 = g.nodes_with_flag(flags::TIER0);

    // Findings: synthetic data has a DCSync service account and DA sessions on workstations.
    let res = evaluate(&g, &tier0, &Cancel::never(), &|_, _| {});
    let ids: Vec<&str> = res.iter().map(|r| r.def.id).collect();
    assert!(ids.contains(&"dcsync-non-tier0"), "{ids:?}");
    assert!(ids.contains(&"privileged-sessions"), "{ids:?}");
    let dcsync = res.iter().find(|r| r.def.id == "dcsync-non-tier0").unwrap();
    assert!(matches!(&dcsync.items, Items::Edges(e) if e.len() == 1));
    // Impact is measured; in this dense synthetic graph the service account has
    // other paths too, so cutting DCSync alone may remove 0 principals' paths.
    assert!(dcsync.exposure.is_some());
    // Sorted by severity first.
    assert!(res.windows(2).all(|w| w[0].def.severity <= w[1].def.severity));

    // Simulation: removing every HasSession edge must reduce exposure.
    let mut removal = Removal::default();
    removal.kinds.insert(ek::HAS_SESSION);
    let sim = simulate(&g, &tier0, &[], &removal);
    assert!(sim.after.exposed_principals < sim.before.exposed_principals);
    assert!(sim.reduction_percent > 0.0);

    // Planner: every step strictly cuts principals, never touches zone membership,
    // and its claimed result matches an independent exposure computation.
    let p = plan(&g, &tier0, &PlanOptions { steps: 5, fixed_kinds: vec![], protect_target_membership: true, ..Default::default() }, &Cancel::never());
    assert!(!p.steps.is_empty());
    let zone = ch_analysis::simulate::expand_membership(&g, &tier0);
    let mut prev = p.baseline;
    let mut all = Removal::default();
    for s in &p.steps {
        assert!(s.principals_cut > 0);
        assert_eq!(s.exposed_after, prev - s.principals_cut);
        prev = s.exposed_after;
        assert!(s.edges.iter().all(|e| e.0 == s.node && !(e.2 == ek::MEMBER_OF && zone.contains(&e.1))));
        all.edges.extend(s.edges.iter().copied());
    }
    let check = ch_analysis::simulate::exposure_with(&g, &zone, &all, 0);
    assert_eq!(check.exposed_principals, p.steps.last().unwrap().exposed_after, "planner cut must be exact");
    let base = ch_analysis::simulate::exposure_with(&g, &zone, &Removal::default(), 0);
    assert_eq!(base.exposed_principals, p.baseline);

    // Fixed kinds are never proposed.
    let p2 = plan(&g, &tier0, &PlanOptions { steps: 3, fixed_kinds: vec![ek::HAS_SESSION], protect_target_membership: true, ..Default::default() }, &Cancel::never());
    assert!(p2.steps.iter().all(|s| s.edges.iter().all(|e| e.2 != ek::HAS_SESSION)));
}
