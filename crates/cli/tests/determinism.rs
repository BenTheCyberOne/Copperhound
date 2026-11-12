//! Reproducibility: the same inputs must give a byte-identical graph and
//! identical analysis output whatever the thread count, parse batch size,
//! order the input files are given in, zip entry order or timing.
//!
//! Ingest numbers nodes by object id and collector-specific edge kinds by
//! name, and merges records in a canonical source order
//! (`ch_ingest::merge::canonical_numbering` / `canonical_source_order`).
//! The inputs below deliberately describe the same objects several times
//! with equal, older, newer and unknown collection times, so the merge order
//! matters (equal-time records merge as a union where the last record's
//! properties win).

use ch_analysis::{findings, report, simulate};
use ch_engine::{tier0_analysis, EdgeFilter};
use ch_ingest::{build_graph, IngestOptions};
use ch_model::flags;
use ch_store::Graph;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ch-determinism-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn pool<R: Send>(threads: usize, f: impl FnOnce() -> R + Send) -> R {
    rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap().install(f)
}

/// Every file of the written graph, by name.
fn graph_files(g: &Graph, dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let _ = fs::remove_dir_all(dir);
    g.write(dir).unwrap();
    let mut out = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let mut bytes = fs::read(e.path()).unwrap();
        if name == "columns.json" {
            // The manifest records how long the build took; nothing else in
            // the graph directory may vary.
            let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            v.as_object_mut().unwrap().remove("build_secs").expect("build_secs");
            bytes = serde_json::to_vec(&v).unwrap();
        }
        out.insert(name, bytes);
    }
    let _ = fs::remove_dir_all(dir);
    out
}

fn assert_same_files(what: &str, a: &BTreeMap<String, Vec<u8>>, b: &BTreeMap<String, Vec<u8>>) {
    assert_eq!(a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>(), "{what}: different graph files");
    for (k, v) in a {
        assert!(*v == b[k], "{what}: {k} differs ({} vs {} bytes)", v.len(), b[k].len());
    }
}

/// Ingest `inputs` with `threads` workers and `batch_bytes` parse batches.
fn ingest(inputs: &[PathBuf], threads: usize, batch_bytes: usize, out: &Path) -> BTreeMap<String, Vec<u8>> {
    pool(threads, || {
        let opts = IngestOptions { batch_bytes, ..Default::default() };
        let b = build_graph(inputs, &opts).expect("ingest");
        assert_eq!(b.ingest.parse_errors, 0, "{:?}", b.ingest.first_error);
        let n = b.graph.node_count() as u32;
        assert!((1..n).all(|i| b.graph.oid(i - 1) < b.graph.oid(i)), "nodes not numbered by object id");
        graph_files(&b.graph, out)
    })
}

/// Tier Zero exposure, the remediation plan, the findings (items in result
/// order) and the Markdown / CSV reports, as one string.
fn analysis(g: &Graph) -> String {
    let mut out = String::new();
    for unified in [true, false] {
        let f = EdgeFilter::traversable(g).unified_tier0(unified);
        out += &serde_json::to_string(&tier0_analysis(g, &f, 50)).unwrap();
        out.push('\n');
    }
    let tier0 = g.nodes_with_flag(flags::TIER0);
    let never = ch_query::Cancel::never();
    let opts = simulate::PlanOptions { steps: 8, fixed_kinds: vec![], protect_target_membership: true, ..Default::default() };
    let plan = simulate::plan(g, &tier0, &opts, &never);
    out += &serde_json::to_string(&plan).unwrap();
    out.push('\n');
    let res = findings::evaluate(g, &tier0, &never, &|_, _| {});
    for r in &res {
        out += &format!("{} {:?} {:?}\n", r.def.id, r.item_labels(g), r.exposure.as_ref().map(|e| (e.principals_cut, e.percent_of_exposed)));
    }
    let rep = simulate::exposure_with(g, &tier0, &ch_analysis::Removal::default(), 10);
    let input = report::ReportInput {
        title: "t",
        generated_at: "2026-01-01T00:00:00Z",
        snapshot_id: "s",
        graph: g,
        tier0: &rep,
        findings: &res,
        posture: &[],
        plan: Some(&plan),
        items_per_finding: 50,
        accepted: &[],
    };
    out += &report::render_markdown(&input);
    out += &report::render_csv(&input);
    out
}

/// Synthetic dumps of one domain (overlapping objects) with equal, newer and
/// unknown collection times, in subdirectories `a` … `d`.
fn multi_dump(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for (sub, seed, stamp) in [("a", 7, Some("20240101000000")), ("b", 8, Some("20240101000000")), ("c", 9, Some("20240301000000")), ("d", 10, None)] {
        let tmp = root.join(format!("gen-{sub}"));
        let cfg = ch_synth::SynthConfig { users: 600, computers: 150, groups: 60, seed };
        ch_synth::generate_with(&cfg, &ch_synth::SynthOptions { domains: 2, rich_props: true }, &tmp).unwrap();
        let dir = root.join("dumps").join(sub);
        fs::create_dir_all(&dir).unwrap();
        for e in fs::read_dir(&tmp).unwrap() {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            let to = match stamp {
                Some(s) => format!("{s}_{name}"),
                None => name,
            };
            fs::rename(e.path(), dir.join(to)).unwrap();
        }
        fs::remove_dir_all(&tmp).unwrap();
        dirs.push(dir);
    }
    dirs
}

fn files_in(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = dirs.iter().flat_map(|d| fs::read_dir(d).unwrap().map(|e| e.unwrap().path())).collect();
    v.sort();
    v
}

/// Deterministic Fisher–Yates shuffle.
fn shuffle<T>(v: &mut [T], mut seed: u64) {
    for i in (1..v.len()).rev() {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        v.swap(i, (seed >> 33) as usize % (i + 1));
    }
}

/// A zip of `files` (entries in the given order) with fixed entry times.
fn zip(files: &[PathBuf], out: &Path) {
    let mut z = zip::ZipWriter::new(fs::File::create(out).unwrap());
    let opts = zip::write::SimpleFileOptions::default().last_modified_time(zip::DateTime::from_date_and_time(2024, 1, 1, 0, 0, 0).unwrap());
    for f in files {
        let parent = f.parent().unwrap().file_name().unwrap().to_string_lossy();
        z.start_file(format!("{parent}/{}", f.file_name().unwrap().to_string_lossy()), opts).unwrap();
        z.write_all(&fs::read(f).unwrap()).unwrap();
    }
    z.finish().unwrap();
    // Same file time for every copy (it is recorded in the source manifest).
    let f = fs::File::options().write(true).open(out).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)).unwrap();
}

fn fixture(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ingest/tests/fixtures/corp").join(sub)
}

#[test]
fn ingest_is_deterministic() {
    let root = scratch("ingest");
    let out = root.join("graph");
    let all = std::thread::available_parallelism().map_or(8, |n| n.get());
    let dirs = multi_dump(&root);
    let dumps = root.join("dumps");

    // Directory input: thread counts and batch sizes (1 byte = one record per batch).
    let reference = ingest(std::slice::from_ref(&dumps), all, 4 << 20, &out);
    for (threads, batch) in [(1, 4 << 20), (2, 4 << 20), (8, 4 << 20), (all, 1), (3, 64 << 10), (8, 1)] {
        let got = ingest(std::slice::from_ref(&dumps), threads, batch, &out);
        assert_same_files(&format!("dir, {threads} threads, batch {batch}"), &reference, &got);
    }
    // The subdirectories in any order.
    let fwd = ingest(&dirs, all, 4 << 20, &out);
    let mut rev = dirs.clone();
    rev.reverse();
    assert_same_files("subdirectories reversed", &fwd, &ingest(&rev, 2, 4 << 20, &out));
    // Individual files, sorted and shuffled (base names collide across
    // subdirectories, so the full path breaks ties).
    let files = files_in(&dirs);
    let sorted = ingest(&files, all, 4 << 20, &out);
    for seed in [1, 2, 3] {
        let mut f = files.clone();
        shuffle(&mut f, seed);
        assert_same_files(&format!("files shuffled ({seed})"), &sorted, &ingest(&f, 1 + seed as usize, 64 << 10, &out));
    }
    // Zip archives with different entry orders.
    let mut zipped = Vec::new();
    for (i, seed) in [0u64, 5, 6].iter().enumerate() {
        let mut f = files.clone();
        if *seed > 0 {
            shuffle(&mut f, *seed);
        }
        let d = root.join(format!("zip{i}"));
        fs::create_dir_all(&d).unwrap();
        zip(&f, &d.join("dump.zip"));
        zipped.push(ingest(&[d.join("dump.zip")], [all, 1, 4][i], 4 << 20, &out));
    }
    assert_same_files("zip entry order", &zipped[0], &zipped[1]);
    assert_same_files("zip entry order", &zipped[0], &zipped[2]);

    // Mixed collectors: SharpHound JSON with LDIF / gzip LDIF of the same domain.
    let mixed = [fixture("sharphound"), fixture("ldif")];
    let a = ingest(&mixed, all, 4 << 20, &out);
    let b = ingest(&[fixture("ldif"), fixture("sharphound")], 1, 1, &out);
    assert_same_files("sharphound + ldif", &a, &b);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn analysis_is_deterministic() {
    let root = scratch("analysis");
    let dirs = multi_dump(&root);
    let all = std::thread::available_parallelism().map_or(8, |n| n.get());
    for inputs in [dirs, vec![fixture("sharphound")], vec![fixture("ldif")]] {
        let mut reference: Option<String> = None;
        for threads in [all, 1, 2, 8] {
            let got = pool(threads, || {
                let b = build_graph(&inputs, &IngestOptions::default()).expect("ingest");
                let _ = b.graph.columns();
                analysis(&b.graph)
            });
            match &reference {
                None => reference = Some(got),
                Some(r) => assert!(*r == got, "analysis output differs with {threads} threads for {inputs:?}"),
            }
        }
    }
    let _ = fs::remove_dir_all(&root);
}
