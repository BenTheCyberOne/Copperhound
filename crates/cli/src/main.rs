use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ch_engine::{reach, shortest_path, tier0_analysis, EdgeFilter};
use ch_model::{flags, NodeKind};
use ch_store::Graph;
use std::path::{Path, PathBuf};
use std::time::Instant;

// The system allocator (notably the Windows heap) serialises under the
// millions of small parallel allocations ingest makes; mimalloc does not.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(
    name = "copperhound",
    version,
    about = "Scalable Active Directory attack-path analysis"
)]
struct Cli {
    /// Worker threads (default: all cores).
    #[arg(long, global = true)]
    threads: Option<usize>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct FilterArgs {
    /// Follow every edge kind, including non-traversable ones.
    #[arg(long)]
    all_edges: bool,
    /// Edge kinds to ignore, comma-separated (e.g. HasSession,CanRDP).
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ingest SharpHound / bloodhound-python / ldapdomaindump / AzureHound output, LDIF
    /// (.ldif, .ldf, .ldif.gz) or AD Explorer snapshots (.dat); files, .zip or directories.
    Ingest {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Output graph directory.
        #[arg(short, long)]
        out: PathBuf,
        /// Directory for extracting zip archives.
        #[arg(long)]
        temp: Option<PathBuf>,
        /// Do not store raw collector properties (smaller graph, no property queries).
        #[arg(long)]
        no_props: bool,
        /// How records of the same object from several dumps combine: `newest`
        /// (newest collection wins, superseded edges dropped) or `union`.
        #[arg(long, default_value = "newest", value_parser = ["newest", "union"])]
        merge: String,
        /// `newest` merge: keep sessions up to this many hours older than a
        /// computer's newest session data.
        #[arg(long, default_value_t = 0)]
        session_window_hours: u64,
    },
    /// Run a CHQL query, printing JSON.
    Query {
        graph: PathBuf,
        query: String,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        /// Evaluate node predicates by scanning properties instead of the
        /// property columns (no predicate pushdown; columns are not loaded).
        #[arg(long)]
        no_pushdown: bool,
        /// Run this many times and report min / median latency.
        #[arg(long, default_value_t = 1)]
        repeat: usize,
        /// Also time the query without pushdown and check the results agree.
        #[arg(long, conflicts_with = "no_pushdown")]
        compare: bool,
    },
    /// Run the REST API and web UI.
    Serve {
        /// Address to listen on.
        #[arg(long, env = "COPPERHOUND_LISTEN", default_value = "127.0.0.1:8080")]
        listen: std::net::SocketAddr,
        /// Data directory (uploads, graphs, marks, admin password).
        #[arg(long, env = "COPPERHOUND_DATA_DIR", default_value = "data")]
        data_dir: PathBuf,
        /// Directory with the built web UI.
        #[arg(long, env = "COPPERHOUND_WEB_DIR", default_value = "web/dist")]
        web_dir: PathBuf,
    },
    /// Evaluate the attack-path findings catalog.
    Findings {
        graph: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Greedy remediation plan: the fixes that cut the most attack paths to Tier Zero.
    Plan {
        graph: PathBuf,
        #[arg(long, default_value_t = 10)]
        steps: usize,
    },
    /// Assessment report (HTML, Markdown or CSV) for a graph.
    Report {
        graph: PathBuf,
        /// Output file; the format follows the extension (.html, .md, .csv).
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value = "Attack path assessment")]
        title: String,
        #[arg(long, default_value_t = 10)]
        plan_steps: usize,
        /// Items listed per finding.
        #[arg(long, default_value_t = 25)]
        items: usize,
    },
    /// Exit 0 if a local server answers /api/v1/health (for container health checks).
    Healthcheck {
        #[arg(long, env = "COPPERHOUND_LISTEN", default_value = "127.0.0.1:8080")]
        listen: std::net::SocketAddr,
    },
    /// Summarise a graph.
    Stats { graph: PathBuf },
    /// Data quality per AD domain / Entra tenant: session, local group and ACL coverage, roles, freshness
    Quality { graph: PathBuf },
    /// Shortest attack path between two objects (name or SID/GUID).
    Path {
        graph: PathBuf,
        #[arg(long)]
        from: String,
        #[arg(long, required_unless_present = "to_tier0")]
        to: Option<String>,
        /// Target the nearest Tier Zero object instead of --to.
        #[arg(long, conflicts_with = "to")]
        to_tier0: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Tier Zero exposure and the choke-point edges that cut the most attack paths.
    Tier0 {
        graph: PathBuf,
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Blast radius: everything reachable from an object.
    Reach {
        graph: PathBuf,
        #[arg(long)]
        from: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Generate a synthetic SharpHound-format dataset for benchmarking.
    Synth {
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = 100_000)]
        users: u32,
        #[arg(long, default_value_t = 20_000)]
        computers: u32,
        #[arg(long, default_value_t = 5_000)]
        groups: u32,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Write one ldapsearch-style LDIF file (`OUT` is the file path)
        /// instead of SharpHound JSON.
        #[arg(long)]
        ldif: bool,
        /// Spread users/computers over this many `domain` property values.
        #[arg(long, default_value_t = 1)]
        domains: u32,
        /// Emit realistic properties (SPNs, logon times, OS, descriptions,
        /// disabled accounts) for property-filter benchmarks.
        #[arg(long)]
        rich_props: bool,
    },
    /// Filter nodes by properties. FILTER is JSON, e.g.
    /// '{"and":[{"kind":"User"},{"truthy":"hasspn"},{"cmp":{"key":"domain","op":"eq","value":"CORP.LOCAL"}}]}'
    Filter {
        graph: PathBuf,
        filter: String,
        /// Print this many matching nodes.
        #[arg(long, default_value_t = 10)]
        limit: usize,
        /// Run this many times and report min / median latency.
        #[arg(long, default_value_t = 1)]
        repeat: usize,
        /// Also time the reference JSON scan (no columns) and check it agrees.
        #[arg(long)]
        scan: bool,
    },
    /// Ranked name search (exact, prefix, substring), as the API's /search.
    Search {
        graph: PathBuf,
        text: String,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 1)]
        repeat: usize,
    },
    /// Load or build a graph's property columns and list them.
    Columns {
        graph: PathBuf,
        /// Delete existing column files first (rebuild from properties).
        #[arg(long)]
        rebuild: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(t) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global()?;
    }
    match cli.cmd {
        Cmd::Ingest {
            inputs,
            out,
            temp,
            no_props,
            merge,
            session_window_hours,
        } => {
            let opts = ch_ingest::IngestOptions {
                temp_dir: temp,
                keep_props: !no_props,
                merge_policy: if merge == "union" { ch_ingest::MergePolicy::Union } else { ch_ingest::MergePolicy::Newest },
                session_window_secs: session_window_hours.saturating_mul(3600),
                ..Default::default()
            };
            ingest(&inputs, &out, &opts)
        }
        Cmd::Query { graph, query, limit, no_pushdown, repeat, compare } => {
            let g = open(&graph)?;
            let opts = ch_query::ExecOptions { pushdown: !no_pushdown, ..Default::default() };
            if opts.pushdown {
                columns_report(&g);
            }
            let cancel = ch_query::Cancel::never();
            let timed = |o: &ch_query::ExecOptions| -> Result<(ch_query::QueryResult, String)> {
                let mut times = Vec::new();
                let mut r = None;
                for _ in 0..repeat.max(1) {
                    let t = Instant::now();
                    r = Some(ch_query::run_opts(&g, &query, limit, ch_query::MAX_LIMIT, &cancel, o).map_err(|e| anyhow!("{e}"))?);
                    times.push(t.elapsed().as_secs_f64() * 1e3);
                }
                Ok((r.expect("ran"), latency(&mut times)))
            };
            let (r, lat) = timed(&opts)?;
            eprintln!("query ran in {lat}{}", if opts.pushdown { "" } else { " (no pushdown)" });
            if compare {
                let (r0, lat0) = timed(&ch_query::ExecOptions { pushdown: false, ..opts })?;
                eprintln!("without pushdown: {lat0}");
                let key = |r: &ch_query::QueryResult| {
                    let mut rows: Vec<String> = r.rows.iter().map(|x| serde_json::to_string(x).unwrap_or_default()).collect();
                    rows.sort();
                    let mut nodes = r.nodes.clone();
                    nodes.sort_unstable();
                    let mut edges = r.edges.clone();
                    edges.sort_unstable();
                    (rows, nodes, edges, r.columns.clone())
                };
                if key(&r) != key(&r0) {
                    eprintln!("results differ (expected only if LIMIT cut a larger result without ORDER BY)");
                }
            }
            let named = |id: u32| serde_json::json!({"id": id, "name": g.name(id), "kind": g.kind(id).as_str()});
            let out = serde_json::json!({
                "nodes": r.nodes.iter().map(|&n| named(n)).collect::<Vec<_>>(),
                "edges": r.edges.iter().map(|e| serde_json::json!({"src": g.name(e.0), "dst": g.name(e.1), "kind": g.edge_kind_name(e.2)})).collect::<Vec<_>>(),
                "paths": r.paths.iter().map(|p| p.iter().map(|&n| g.name(n)).collect::<Vec<_>>()).collect::<Vec<_>>(),
                "columns": r.columns,
                "rows": r.rows,
                "truncated": r.truncated,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        Cmd::Findings { graph, json } => {
            let g = open(&graph)?;
            let tier0 = g.nodes_with_flag(flags::TIER0);
            let t = Instant::now();
            let res = ch_analysis::findings::evaluate(&g, &tier0, &ch_query::Cancel::never(), &|_, _| {});
            let secs = t.elapsed().as_secs_f64();
            if json {
                let out: Vec<_> = res
                    .iter()
                    .map(|f| serde_json::json!({"id": f.def.id, "severity": f.def.severity, "title": f.def.title, "count": f.items.len(), "exposure": f.exposure}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("{} findings in {secs:.2}s", res.len());
                for f in &res {
                    let sev = serde_json::to_value(f.def.severity)?.as_str().unwrap_or("").to_uppercase();
                    let impact = f
                        .exposure
                        .as_ref()
                        .map(|e| format!("  fixes {} principals ({:.1}%)", num(e.principals_cut), e.percent_of_exposed))
                        .unwrap_or_default();
                    println!("  {sev:<8} {:<62} {:>10}{impact}", f.def.title, num(f.items.len() as u64));
                }
            }
            Ok(())
        }
        Cmd::Plan { graph, steps } => {
            let g = open(&graph)?;
            let tier0 = g.nodes_with_flag(flags::TIER0);
            let t = Instant::now();
            let opts = ch_analysis::simulate::PlanOptions { steps, fixed_kinds: vec![], protect_target_membership: true };
            let p = ch_analysis::simulate::plan(&g, &tier0, &opts, &ch_query::Cancel::never());
            println!("baseline exposed principals: {}   ({:.2}s)", num(p.baseline), t.elapsed().as_secs_f64());
            for (i, s) in p.steps.iter().enumerate() {
                println!(
                    "  {:>2}. sever {} ({}): cuts {} principals → {} exposed ({:.1}% total cut)",
                    i + 1,
                    g.name(s.node),
                    g.kind(s.node).as_str(),
                    num(s.principals_cut),
                    num(s.exposed_after),
                    s.cumulative_reduction_percent
                );
                for e in s.edges.iter().take(5) {
                    println!("        remove {} -[{}]-> {}", g.name(e.0), g.edge_kind_name(e.2), g.name(e.1));
                }
                if s.edges.len() > 5 {
                    println!("        … and {} more edges", s.edges.len() - 5);
                }
            }
            Ok(())
        }
        Cmd::Report { graph, out, title, plan_steps, items } => {
            let g = open(&graph)?;
            let t = Instant::now();
            let tier0 = g.nodes_with_flag(flags::TIER0);
            let never = ch_query::Cancel::never();
            let findings = ch_analysis::findings::evaluate(&g, &tier0, &never, &|_, _| {});
            let rep = ch_analysis::simulate::exposure_with(&g, &tier0, &ch_analysis::Removal::default(), 10);
            let ext = out.extension().and_then(|e| e.to_str()).unwrap_or("html").to_ascii_lowercase();
            let plan = (plan_steps > 0 && ext != "csv").then(|| {
                let opts = ch_analysis::simulate::PlanOptions { steps: plan_steps, fixed_kinds: vec![], protect_target_membership: true };
                ch_analysis::simulate::plan(&g, &tier0, &opts, &never)
            });
            let generated = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
            let snap = graph.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let input = ch_analysis::report::ReportInput {
                title: &title,
                generated_at: &generated,
                snapshot_id: &snap,
                graph: &g,
                tier0: &rep,
                findings: &findings,
                posture: &[],
                plan: plan.as_ref(),
                items_per_finding: items,
                accepted: &[],
            };
            let text = match ext.as_str() {
                "md" | "markdown" => ch_analysis::report::render_markdown(&input),
                "csv" => ch_analysis::report::render_csv(&input),
                "html" | "htm" => ch_analysis::report::render_html(&input),
                other => anyhow::bail!("unsupported report extension .{other} (use .html, .md or .csv)"),
            };
            std::fs::write(&out, text)?;
            eprintln!("report → {} ({} findings, {:.2}s)", out.display(), findings.len(), t.elapsed().as_secs_f64());
            Ok(())
        }
        Cmd::Healthcheck { listen } => {
            use std::io::{Read, Write};
            let mut addr = listen;
            if addr.ip().is_unspecified() {
                addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
            }
            let mut s = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))?;
            // With built-in HTTPS, a listening socket is the health signal.
            let tls = std::env::var("COPPERHOUND_TLS_CERT").is_ok_and(|v| !v.is_empty())
                || std::env::var("COPPERHOUND_TLS").is_ok_and(|v| v.eq_ignore_ascii_case("self-signed"));
            if tls {
                return Ok(());
            }
            s.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
            s.write_all(b"GET /api/v1/health HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
            let mut buf = String::new();
            s.read_to_string(&mut buf)?;
            if buf.starts_with("HTTP/1.0 200") || buf.starts_with("HTTP/1.1 200") {
                Ok(())
            } else {
                bail!("unhealthy: {}", buf.lines().next().unwrap_or(""))
            }
        }
        Cmd::Serve {
            listen,
            data_dir,
            web_dir,
        } => {
            ch_server::init_tracing();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(ch_server::serve(ch_server::ServerConfig {
                    listen,
                    data_dir,
                    web_dir: Some(web_dir),
                }))
        }
        Cmd::Stats { graph } => stats(&graph),
        Cmd::Quality { graph } => {
            let g = Graph::open(&graph)?;
            let sources: Vec<serde_json::Value> =
                g.meta().ingest.as_ref().and_then(|m| m.get("sources")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
            println!("{}", serde_json::to_string_pretty(&ch_server::quality::compute(&g, &sources))?);
            Ok(())
        }
        Cmd::Path {
            graph,
            from,
            to,
            to_tier0,
            filter,
        } => path(&graph, &from, to.as_deref(), to_tier0, &filter),
        Cmd::Tier0 {
            graph,
            top,
            json,
            filter,
        } => tier0(&graph, top, json, &filter),
        Cmd::Reach {
            graph,
            from,
            filter,
        } => reach_cmd(&graph, &from, &filter),
        Cmd::Synth {
            out,
            users,
            computers,
            groups,
            seed,
            ldif,
            domains,
            rich_props,
        } => {
            let t = Instant::now();
            let cfg = ch_synth::SynthConfig {
                users,
                computers,
                groups,
                seed,
            };
            let s = if ldif {
                if domains > 1 || rich_props {
                    anyhow::bail!("--domains / --rich-props apply to SharpHound JSON output, not --ldif");
                }
                ch_synth::generate_ldif(&cfg, &out)?
            } else {
                ch_synth::generate_with(&cfg, &ch_synth::SynthOptions { domains, rich_props }, &out)?
            };
            println!(
                "generated {} objects, {} in {:.2}s → {}",
                num(s.objects),
                bytes(s.bytes),
                t.elapsed().as_secs_f64(),
                out.display()
            );
            println!("DCSync-capable service account: {}", s.service_account);
            Ok(())
        }
        Cmd::Filter {
            graph,
            filter,
            limit,
            repeat,
            scan,
        } => {
            let f: ch_store::Filter = serde_json::from_str(&filter).context("parsing filter JSON")?;
            let g = open(&graph)?;
            columns_report(&g);
            let mut times = Vec::new();
            let mut hits = ch_store::RoaringBitmap::new();
            for _ in 0..repeat.max(1) {
                let t = Instant::now();
                hits = g.filter(&f);
                times.push(t.elapsed().as_secs_f64() * 1e3);
            }
            println!("matches    {}", num(hits.len()));
            println!("filter     {}", latency(&mut times));
            if scan {
                let t = Instant::now();
                let reference = g.filter_scan(&f);
                println!("json scan  {:.1} ms", t.elapsed().as_secs_f64() * 1e3);
                if reference != hits {
                    bail!("indexed result differs from the reference scan ({} vs {})", hits.len(), reference.len());
                }
            }
            for id in hits.iter().take(limit) {
                println!("  {id:>10}  {} ({})", g.name(id), g.kind(id).as_str());
            }
            Ok(())
        }
        Cmd::Search {
            graph,
            text,
            kind,
            limit,
            repeat,
        } => {
            let g = open(&graph)?;
            let kind = kind.as_deref().map(NodeKind::parse).filter(|k| *k != NodeKind::Unknown);
            columns_report(&g);
            let mut times = Vec::new();
            let mut ids = Vec::new();
            for _ in 0..repeat.max(1) {
                let t = Instant::now();
                ids = g.search(&text, kind, limit);
                times.push(t.elapsed().as_secs_f64() * 1e3);
            }
            println!("search     {}", latency(&mut times));
            for id in ids {
                println!("  {id:>10}  {} ({})", g.name(id), g.kind(id).as_str());
            }
            Ok(())
        }
        Cmd::Columns { graph, rebuild } => {
            if rebuild {
                for f in ["columns.json", "columns.bin"] {
                    let _ = std::fs::remove_file(graph.join(f));
                }
            }
            let g = open(&graph)?;
            let c = columns_report(&g);
            println!("{:<40} {:<6} {:>12} {:>10}", "key", "type", "non-null", "distinct");
            for i in c.info() {
                let ty = serde_json::to_value(i.ty)?.as_str().unwrap_or("").to_string();
                let distinct = i.distinct.map(|d| num(d) + if i.eq_index { "*" } else { "" }).unwrap_or_default();
                println!("{:<40} {:<6} {:>12} {:>10}", i.key, ty, num(i.count), distinct);
            }
            println!("(* = equality index)");
            Ok(())
        }
    }
}

/// Load or build the property columns, printing how long it took.
fn columns_report(g: &Graph) -> &ch_store::Columns {
    let t = Instant::now();
    let c = g.columns();
    let o = &c.origin;
    eprintln!(
        "columns    {} in {:.0} ms ({} columns, {}{})",
        if o.loaded { "loaded" } else { "built" },
        t.elapsed().as_secs_f64() * 1e3,
        c.info().len(),
        bytes(o.bytes),
        o.persist_error.as_deref().map(|e| format!("; not persisted: {e}")).unwrap_or_default()
    );
    c
}

fn latency(times: &mut [f64]) -> String {
    times.sort_by(f64::total_cmp);
    let med = times[times.len() / 2];
    if times.len() == 1 {
        format!("{med:.2} ms")
    } else {
        format!("min {:.2} ms, median {med:.2} ms ({} runs)", times[0], times.len())
    }
}

fn num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn bytes(b: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < units.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", units[u])
}

fn open(graph: &Path) -> Result<Graph> {
    let t = Instant::now();
    let g = Graph::open(graph).with_context(|| format!("opening graph {}", graph.display()))?;
    eprintln!(
        "opened {} nodes / {} edges in {:.0} ms",
        num(g.node_count() as u64),
        num(g.edge_count() as u64),
        t.elapsed().as_secs_f64() * 1e3
    );
    Ok(g)
}

fn filter(g: &Graph, a: &FilterArgs) -> Result<EdgeFilter> {
    let mut f = if a.all_edges {
        EdgeFilter::all(g)
    } else {
        EdgeFilter::traversable(g)
    };
    for k in &a.exclude {
        f.set(g, k.trim(), false)?;
    }
    Ok(f)
}

fn resolve(g: &Graph, q: &str) -> Result<u32> {
    g.lookup(q)
        .ok_or_else(|| anyhow!("no object named or identified by '{q}'"))
}

fn label(g: &Graph, id: u32) -> String {
    let mut s = format!("{} ({})", g.name(id), g.kind(id).as_str());
    if g.has_flag(id, flags::TIER0) {
        s.push_str(" [T0]");
    }
    s
}

fn ingest(inputs: &[PathBuf], out: &Path, opts: &ch_ingest::IngestOptions) -> Result<()> {
    let total = Instant::now();
    let built = ch_ingest::build_graph(inputs, opts)?;
    let r = &built.ingest;
    println!(
        "files      {} ({} from zips), {}",
        r.files,
        r.zip_entries,
        bytes(r.bytes)
    );
    println!("records    {}", num(r.records));
    if r.parse_errors > 0 {
        println!(
            "errors     {} (first: {})",
            num(r.parse_errors),
            r.first_error.as_deref().unwrap_or("?")
        );
    }
    if r.dn_edges_resolved + r.dn_edges_unresolved > 0 {
        println!(
            "DN refs    {} resolved, {} unresolved",
            num(r.dn_edges_resolved),
            num(r.dn_edges_unresolved)
        );
    }
    println!("nodes      {}", num(r.nodes as u64));
    let dated = r.sources.iter().filter(|s| s.collected_at.is_some()).count();
    println!(
        "merge      {} — {} sources ({} dated), {} superseded records, {} superseded edge records",
        r.merge_policy,
        r.sources.len(),
        dated,
        num(r.superseded_objects),
        num(r.superseded_edges)
    );
    println!("tier zero  {}", num(r.tier0_nodes));
    println!("dcsync     {} derived edges", num(r.dcsync_edges));
    let throughput = r.bytes as f64 / r.parse_secs.max(1e-9) / (1 << 20) as f64;
    println!(
        "parse      {:.2}s ({throughput:.0} MB/s; scan {:.2}s)   unzip {:.2}s   merge {:.2}s (renumber {:.2}s)",
        r.parse_secs, r.scan_secs, r.extract_secs, r.merge_secs, r.renumber_secs
    );

    let b = &built.build;
    println!(
        "edges      {} unique of {} raw   csr {:.2}s   index {:.2}s",
        num(b.edges),
        num(b.raw_edges),
        b.csr_secs,
        b.index_secs
    );
    let derived: Vec<String> = built
        .post
        .passes
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(p, n)| format!("{p} {}", num(*n)))
        .collect();
    if !derived.is_empty() {
        println!("derived    {}   ({:.2}s)", derived.join(", "), built.post.secs);
    }
    let g = &built.graph;
    let t = Instant::now();
    let c = g.columns();
    println!(
        "columns    {} property columns, {} in {:.2}s",
        c.info().len(),
        bytes(c.origin.bytes),
        t.elapsed().as_secs_f64()
    );
    let t = Instant::now();
    g.write(out)?;
    println!(
        "write      {:.2}s → {}",
        t.elapsed().as_secs_f64(),
        out.display()
    );
    println!("total      {:.2}s", total.elapsed().as_secs_f64());
    Ok(())
}

fn stats(graph: &Path) -> Result<()> {
    let g = open(graph)?;
    let mut kinds = [0u64; NodeKind::COUNT];
    for &k in g.kinds() {
        kinds[(k as usize).min(NodeKind::COUNT - 1)] += 1;
    }
    println!("nodes {}", num(g.node_count() as u64));
    for (i, k) in NodeKind::ALL.iter().enumerate() {
        if kinds[i] > 0 {
            println!("  {:<16} {:>14}", k.as_str(), num(kinds[i]));
        }
    }
    let mut ek = vec![0u64; g.edge_kind_count()];
    for &k in g.all_edge_kinds() {
        ek[k as usize] += 1;
    }
    let mut ek: Vec<(usize, u64)> = ek.into_iter().enumerate().filter(|(_, c)| *c > 0).collect();
    ek.sort_by_key(|e| std::cmp::Reverse(e.1));
    println!("edges {}", num(g.edge_count() as u64));
    for (k, c) in ek {
        let t = if g.is_traversable(k as u16) {
            ""
        } else {
            "  (non-traversable)"
        };
        println!("  {:<24} {:>14}{t}", g.edge_kind_name(k as u16), num(c));
    }
    println!(
        "tier zero {}",
        num(g.nodes_with_flag(flags::TIER0).len() as u64)
    );
    Ok(())
}

fn path(graph: &Path, from: &str, to: Option<&str>, to_tier0: bool, fa: &FilterArgs) -> Result<()> {
    let g = open(graph)?;
    let f = filter(&g, fa)?;
    let src = resolve(&g, from)?;
    let targets = if to_tier0 {
        let t = g.nodes_with_flag(flags::TIER0);
        if t.is_empty() {
            bail!("graph has no Tier Zero objects");
        }
        t
    } else {
        vec![resolve(&g, to.expect("clap enforces --to or --to-tier0"))?]
    };
    let t = Instant::now();
    let res = shortest_path(&g, &[src], &targets, &f);
    let ms = t.elapsed().as_secs_f64() * 1e3;
    match res {
        None => println!("no path ({ms:.2} ms)"),
        Some(p) => {
            println!(
                "{} hops, explored {} nodes in {ms:.2} ms",
                p.kinds.len(),
                num(p.explored as u64)
            );
            println!("  {}", label(&g, p.nodes[0]));
            for (i, k) in p.kinds.iter().enumerate() {
                println!(
                    "    -[{}]-> {}",
                    g.edge_kind_name(*k),
                    label(&g, p.nodes[i + 1])
                );
            }
        }
    }
    Ok(())
}

fn tier0(graph: &Path, top: usize, json: bool, fa: &FilterArgs) -> Result<()> {
    let g = open(graph)?;
    let f = filter(&g, fa)?;
    let t = Instant::now();
    let r = tier0_analysis(&g, &f, top);
    let secs = t.elapsed().as_secs_f64();
    if json {
        let choke: Vec<_> = r
            .choke_points
            .iter()
            .map(|c| {
                serde_json::json!({
                    "src": g.name(c.src), "src_kind": g.kind(c.src).as_str(),
                    "edge": g.edge_kind_name(c.kind),
                    "dst": g.name(c.dst), "dst_kind": g.kind(c.dst).as_str(),
                    "principals_routed": c.flow,
                })
            })
            .collect();
        let out = serde_json::json!({
            "tier0_nodes": r.tier0_nodes, "max_depth": r.max_depth,
            "exposed_principals": r.exposed_principals, "exposure": r.exposure,
            "choke_points": choke, "seconds": secs,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    println!(
        "Tier Zero objects: {}   longest shortest-path: {} hops   ({secs:.2}s)",
        num(r.tier0_nodes),
        r.max_depth
    );
    println!("\nObjects with an attack path to Tier Zero:");
    for e in &r.exposure {
        let pct = 100.0 * e.with_path as f64 / e.total.max(1) as f64;
        println!(
            "  {:<12} {:>12} / {:<12} {pct:5.1}%",
            e.kind,
            num(e.with_path),
            num(e.total)
        );
    }
    println!("\nTop choke points (users+computers whose shortest paths cross the edge):");
    for c in &r.choke_points {
        println!(
            "  {:>12.1}  {} -[{}]-> {}",
            c.flow,
            label(&g, c.src),
            g.edge_kind_name(c.kind),
            label(&g, c.dst)
        );
    }
    Ok(())
}

fn reach_cmd(graph: &Path, from: &str, fa: &FilterArgs) -> Result<()> {
    let g = open(graph)?;
    let f = filter(&g, fa)?;
    let src = resolve(&g, from)?;
    let t = Instant::now();
    let r = reach(&g, &[src], &f);
    println!(
        "{} reaches {} objects ({} Tier Zero), max depth {} — {:.2} ms",
        label(&g, src),
        num(r.reachable),
        num(r.tier0_reached),
        r.max_depth,
        t.elapsed().as_secs_f64() * 1e3
    );
    for k in &r.by_kind {
        println!("  {:<12} {:>12}", k.kind, num(k.with_path));
    }
    Ok(())
}
