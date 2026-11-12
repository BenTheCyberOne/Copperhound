//! Assessment reports: a self-contained HTML document (inline CSS and SVG
//! charts, print styles so "Print → Save as PDF" gives a clean PDF), a
//! Markdown version for tickets and wikis, and a CSV of every finding item.

use crate::findings::{FindingResult, Items, Severity};
use crate::posture::Snapshot;
use crate::simulate::Plan;
use crate::{edge_label, EdgeKey};
use ch_engine::Tier0Report;
use ch_store::Graph;
use std::fmt::Write as _;

pub struct ReportInput<'a> {
    pub title: &'a str,
    pub generated_at: &'a str,
    pub snapshot_id: &'a str,
    pub graph: &'a Graph,
    pub tier0: &'a Tier0Report,
    pub findings: &'a [FindingResult],
    /// Oldest first.
    pub posture: &'a [Snapshot],
    pub plan: Option<&'a Plan>,
    /// Items listed per finding in the appendix.
    pub items_per_finding: usize,
    /// Findings accepted as risks (left out of `findings`).
    pub accepted: &'a [AcceptedRisk],
}

/// A finding accepted as a risk, listed separately in the report.
#[derive(Debug, Clone)]
pub struct AcceptedRisk {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub items: usize,
    pub reason: String,
    pub accepted_by: String,
    pub accepted_at: String,
    pub expires_at: Option<String>,
}

fn sev_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn num(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    o
}

fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

/// " to OT controllers" for impact measured against another target than Tier Zero.
fn target_suffix(target: &str) -> String {
    if target == crate::findings::TIER0_LABEL {
        String::new()
    } else {
        format!(" to {target}")
    }
}

/// Letter grade and the rule that produced it.
pub fn grade(exposure_percent: f64, critical: usize, high: usize) -> (char, &'static str) {
    if exposure_percent >= 50.0 || critical >= 3 {
        ('F', "half or more of all principals can reach Tier Zero, or three or more critical findings")
    } else if exposure_percent >= 20.0 || critical > 0 {
        ('D', "a fifth or more of principals can reach Tier Zero, or a critical finding is open")
    } else if exposure_percent >= 5.0 || high > 0 {
        ('C', "more than 5% of principals can reach Tier Zero, or a high finding is open")
    } else if exposure_percent > 0.0 {
        ('B', "a small number of principals can reach Tier Zero")
    } else {
        ('A', "no principal outside Tier Zero has an attack path to it")
    }
}

struct Summary {
    exposure_percent: f64,
    by_sev: [usize; 4],
    grade: (char, &'static str),
}

fn summary(r: &ReportInput) -> Summary {
    let mut by_sev = [0usize; 4];
    for f in r.findings {
        by_sev[f.def.severity as usize] += 1;
    }
    let exposure_percent = pct(r.tier0.exposed_principals, r.tier0.total_principals);
    Summary { exposure_percent, by_sev, grade: grade(exposure_percent, by_sev[0], by_sev[1]) }
}

fn item_lines(g: &Graph, f: &FindingResult, limit: usize) -> Vec<String> {
    match &f.items {
        Items::Edges(es) => es.iter().take(limit).map(|&e: &EdgeKey| edge_label(g, e)).collect(),
        Items::Nodes(ns) => ns.iter().take(limit).map(|&n| format!("{} ({})", g.name(n), g.kind(n).as_str())).collect(),
    }
}

// ---------------------------------------------------------------- SVG

const W: f64 = 640.0;
const H: f64 = 180.0;
const PAD: f64 = 36.0;

fn line_chart(points: &[(String, f64)], unit: &str) -> String {
    if points.len() < 2 {
        return "<p class=\"muted\">The trend chart appears after two or more ingests.</p>".into();
    }
    let max = points.iter().map(|p| p.1).fold(0.0f64, f64::max).max(1e-9) * 1.1;
    let x = |i: usize| PAD + (W - 2.0 * PAD) * i as f64 / (points.len() - 1) as f64;
    let y = |v: f64| H - PAD + 8.0 - (H - 2.0 * PAD) * v / max;
    let mut s = format!("<svg viewBox=\"0 0 {W} {H}\" class=\"chart\" role=\"img\" aria-label=\"trend\">");
    let _ = write!(s, "<line x1=\"{PAD}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" class=\"axis\"/>", H - PAD + 8.0, W - PAD, H - PAD + 8.0);
    let path: Vec<String> = points.iter().enumerate().map(|(i, p)| format!("{:.1},{:.1}", x(i), y(p.1))).collect();
    let _ = write!(s, "<polyline points=\"{}\" class=\"line\"/>", path.join(" "));
    for (i, p) in points.iter().enumerate() {
        let _ = write!(
            s,
            "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"3\" class=\"dot\"><title>{}: {:.1}{unit}</title></circle>",
            x(i),
            y(p.1),
            esc(&p.0),
            p.1
        );
    }
    let first = &points[0];
    let last = points.last().expect("len >= 2");
    let _ = write!(s, "<text x=\"{PAD}\" y=\"{}\" class=\"lbl\">{}</text>", H - 6.0, esc(&first.0));
    let _ = write!(s, "<text x=\"{}\" y=\"{}\" class=\"lbl\" text-anchor=\"end\">{}</text>", W - PAD, H - 6.0, esc(&last.0));
    let _ = write!(s, "<text x=\"{:.1}\" y=\"{:.1}\" class=\"val\" text-anchor=\"end\">{:.1}{unit}</text>", x(points.len() - 1), y(last.1) - 8.0, last.1);
    s.push_str("</svg>");
    s
}

fn bar_chart(bars: &[(String, f64)], unit: &str) -> String {
    if bars.is_empty() {
        return String::new();
    }
    let row = 22.0;
    let label_w = 230.0;
    let h = row * bars.len() as f64 + 8.0;
    let max = bars.iter().map(|b| b.1).fold(0.0f64, f64::max).max(1e-9);
    let mut s = format!("<svg viewBox=\"0 0 {W} {h}\" class=\"chart\" role=\"img\" aria-label=\"bars\">");
    for (i, (l, v)) in bars.iter().enumerate() {
        let y = 4.0 + row * i as f64;
        let bw = (W - label_w - 70.0) * v / max;
        let short: String = if l.chars().count() > 34 { l.chars().take(33).collect::<String>() + "…" } else { l.clone() };
        let _ = write!(s, "<text x=\"{}\" y=\"{}\" class=\"lbl\" text-anchor=\"end\">{}<title>{}</title></text>", label_w - 8.0, y + 14.0, esc(&short), esc(l));
        let _ = write!(s, "<rect x=\"{label_w}\" y=\"{}\" width=\"{bw:.1}\" height=\"{}\" class=\"bar\"/>", y + 2.0, row - 6.0);
        let _ = write!(s, "<text x=\"{:.1}\" y=\"{}\" class=\"val\">{:.1}{unit}</text>", label_w + bw + 6.0, y + 14.0, v);
    }
    s.push_str("</svg>");
    s
}

// --------------------------------------------------------------- HTML

const CSS: &str = r#"
:root{--fg:#1d2330;--muted:#5d6678;--line:#d9dde5;--bg:#fff;--panel:#f5f7fa;--accent:#a4502a;
--crit:#b3261e;--high:#d0570f;--med:#a77a00;--low:#3c6e9f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:15px;margin:22px 0 6px}.muted{color:var(--muted)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.kpi b{display:block;font-size:24px;line-height:1.2}.kpi span{color:var(--muted);font-size:12px}
.grade{font-size:40px!important;color:var(--accent)}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}td.n{text-align:right;white-space:nowrap}
.sev{display:inline-block;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:600;color:#fff;text-transform:uppercase}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}.sev.low{background:var(--low)}
.finding{border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0;break-inside:avoid}
.finding p{margin:6px 0}.items{font:12px/1.45 ui-monospace,Consolas,monospace;background:var(--panel);padding:8px 10px;border-radius:6px;white-space:pre-wrap;word-break:break-all}
.chart{width:100%;height:auto}.axis{stroke:var(--line)}.line{fill:none;stroke:var(--accent);stroke-width:2}.dot{fill:var(--accent)}
.bar{fill:var(--accent);opacity:.85}.lbl{font-size:11px;fill:var(--muted)}.val{font-size:11px;fill:var(--fg)}
code{font:12px ui-monospace,Consolas,monospace}
@media print{main{padding:0;max-width:none}h2{break-after:avoid}.finding,.kpis,table{break-inside:avoid}a{color:inherit;text-decoration:none}}
"#;

pub fn render_html(r: &ReportInput) -> String {
    let g = r.graph;
    let sm = summary(r);
    let mut h = String::with_capacity(64 << 10);
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{CSS}</style></head><body><main>",
        esc(r.title)
    );
    let _ = write!(
        h,
        "<h1>{}</h1><p class=\"muted\">Generated {} · snapshot <code>{}</code> · {} objects, {} relationships · CopperHound</p>",
        esc(r.title),
        esc(r.generated_at),
        esc(r.snapshot_id),
        num(g.node_count() as u64),
        num(g.edge_count() as u64)
    );

    // Executive summary
    h.push_str("<h2>Executive summary</h2><div class=\"kpis\">");
    let _ = write!(h, "<div class=\"kpi\"><b class=\"grade\">{}</b><span>Posture grade</span></div>", sm.grade.0);
    let _ = write!(
        h,
        "<div class=\"kpi\"><b>{:.1}%</b><span>{} of {} principals have an attack path to Tier Zero</span></div>",
        sm.exposure_percent,
        num(r.tier0.exposed_principals),
        num(r.tier0.total_principals)
    );
    let _ = write!(h, "<div class=\"kpi\"><b>{}</b><span>Tier Zero objects</span></div>", num(r.tier0.tier0_nodes));
    let _ = write!(
        h,
        "<div class=\"kpi\"><b>{}</b><span>findings: {} critical · {} high · {} medium · {} low</span></div></div>",
        r.findings.len(),
        sm.by_sev[0],
        sm.by_sev[1],
        sm.by_sev[2],
        sm.by_sev[3]
    );
    let _ = write!(h, "<p>Grade {}: {}.</p>", sm.grade.0, sm.grade.1);
    // Tier Zero impact only: other targets (OT controllers) are not comparable.
    let mut top: Vec<&FindingResult> = r
        .findings
        .iter()
        .filter(|f| f.exposure.as_ref().is_some_and(|e| e.principals_cut > 0 && e.target == crate::findings::TIER0_LABEL))
        .collect();
    top.sort_by(|a, b| {
        let (x, y) = (a.exposure.as_ref().map_or(0, |e| e.principals_cut), b.exposure.as_ref().map_or(0, |e| e.principals_cut));
        y.cmp(&x)
    });
    if let Some(f) = top.first() {
        let e = f.exposure.as_ref().expect("filtered");
        let _ = write!(
            h,
            "<p><b>Highest-impact fix:</b> {} — resolving it removes every attack path for {} principals ({:.1}% of current exposure).</p>",
            esc(f.def.title),
            num(e.principals_cut),
            e.percent_of_exposed
        );
    }
    if let Some(p) = r.plan.filter(|p| !p.steps.is_empty()) {
        let last = p.steps.last().expect("non-empty");
        let _ = write!(
            h,
            "<p><b>Remediation plan:</b> the {} fixes in section 3 cut exposure by {:.1}% ({} → {} principals).</p>",
            p.steps.len(),
            last.cumulative_reduction_percent,
            num(p.baseline),
            num(last.exposed_after)
        );
    }

    // Findings overview
    h.push_str("<h2>1. Findings</h2>");
    if r.findings.is_empty() {
        h.push_str("<p>No findings.</p>");
    } else {
        h.push_str("<table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th class=\"n\">Items</th><th class=\"n\">Fix removes</th></tr></thead><tbody>");
        for f in r.findings {
            let s = sev_str(f.def.severity);
            let impact = f
                .exposure
                .as_ref()
                .map(|e| format!("{:.1}% <span class=\"muted\">({}){}</span>", e.percent_of_exposed, num(e.principals_cut), target_suffix(e.target)))
                .unwrap_or_else(|| "—".into());
            let _ = write!(
                h,
                "<tr><td><span class=\"sev {s}\">{s}</span></td><td><a href=\"#f-{}\">{}</a></td><td>{}</td><td class=\"n\">{}{}</td><td class=\"n\">{impact}</td></tr>",
                esc(f.def.id),
                esc(f.def.title),
                esc(f.def.category),
                num(f.items.len() as u64),
                if f.truncated { "+" } else { "" }
            );
        }
        h.push_str("</tbody></table>");
        let bars: Vec<(String, f64)> =
            top.iter().take(10).map(|f| (f.def.title.to_string(), f.exposure.as_ref().map_or(0.0, |e| e.percent_of_exposed))).collect();
        if !bars.is_empty() {
            h.push_str("<h3>Exposure removed by fixing each finding</h3>");
            h.push_str(&bar_chart(&bars, "%"));
        }
    }

    if !r.accepted.is_empty() {
        h.push_str("<h3>Accepted risks</h3><p class=\"muted\">Findings accepted as risks; not counted above.</p><table><thead><tr><th>Severity</th><th>Finding</th><th class=\"n\">Items</th><th>Reason</th><th>Accepted by</th><th>Expires</th></tr></thead><tbody>");
        for a in r.accepted {
            let s = sev_str(a.severity);
            let _ = write!(
                h,
                "<tr><td><span class=\"sev {s}\">{s}</span></td><td>{}</td><td class=\"n\">{}</td><td>{}</td><td>{} <span class=\"muted\">{}</span></td><td>{}</td></tr>",
                esc(&a.title),
                num(a.items as u64),
                esc(&a.reason),
                esc(&a.accepted_by),
                esc(&a.accepted_at),
                esc(a.expires_at.as_deref().unwrap_or("never"))
            );
        }
        h.push_str("</tbody></table>");
    }

    // Posture
    h.push_str("<h2>2. Posture over time</h2>");
    let pts: Vec<(String, f64)> = r.posture.iter().map(|s| (s.created_at.chars().take(10).collect(), s.exposure_percent)).collect();
    h.push_str("<h3>Principals with a path to Tier Zero</h3>");
    h.push_str(&line_chart(&pts, "%"));
    if !r.posture.is_empty() {
        h.push_str("<table><thead><tr><th>Snapshot</th><th class=\"n\">Objects</th><th class=\"n\">Exposed</th><th class=\"n\">Exposure</th><th class=\"n\">Critical</th><th class=\"n\">High</th></tr></thead><tbody>");
        for s in r.posture.iter().rev().take(12) {
            let c = |k: &str| s.findings.get(k).copied().unwrap_or(0);
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{:.1}%</td><td class=\"n\">{}</td><td class=\"n\">{}</td></tr>",
                esc(&s.created_at),
                num(s.nodes),
                num(s.exposed_principals),
                s.exposure_percent,
                c("critical"),
                c("high")
            );
        }
        h.push_str("</tbody></table>");
    }

    // Plan
    h.push_str("<h2>3. Remediation plan</h2>");
    match r.plan {
        Some(p) if !p.steps.is_empty() => {
            h.push_str("<p class=\"muted\">Ordered by impact. Each step removes every attack path for the principals it cuts; the counts are exact, not estimates.</p>");
            let bars: Vec<(String, f64)> =
                p.steps.iter().enumerate().map(|(i, s)| (format!("{}. {}", i + 1, g.name(s.node)), s.cumulative_reduction_percent)).collect();
            h.push_str(&bar_chart(&bars, "%"));
            h.push_str("<table><thead><tr><th>#</th><th>Sever</th><th>Edges to remove</th><th class=\"n\">Cuts</th><th class=\"n\">Total cut</th></tr></thead><tbody>");
            for (i, s) in p.steps.iter().enumerate() {
                let edges: Vec<String> = s.edges.iter().take(4).map(|&e| esc(&edge_label(g, e))).collect();
                let more = if s.edges.len() > 4 { format!("<br><span class=\"muted\">… and {} more</span>", s.edges.len() - 4) } else { String::new() };
                let _ = write!(
                    h,
                    "<tr><td>{}</td><td>{} <span class=\"muted\">({}){}</span></td><td><code>{}</code>{more}</td><td class=\"n\">{}</td><td class=\"n\">{:.1}%</td></tr>",
                    i + 1,
                    esc(g.name(s.node)),
                    g.kind_name(s.node),
                    if s.needs_window { " · maintenance window" } else { "" },
                    edges.join("<br>"),
                    num(s.principals_cut),
                    s.cumulative_reduction_percent
                );
            }
            h.push_str("</tbody></table>");
        }
        _ => h.push_str("<p>No remediation steps: nothing is exposed, or the plan was not computed.</p>"),
    }

    // Choke points
    if !r.tier0.choke_points.is_empty() {
        h.push_str("<h2>4. Choke points</h2><p class=\"muted\">Relationships carrying the most shortest attack paths into Tier Zero.</p>");
        h.push_str("<table><thead><tr><th>From</th><th>Relationship</th><th>To</th><th class=\"n\">Paths routed</th></tr></thead><tbody>");
        for c in &r.tier0.choke_points {
            let _ = write!(
                h,
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td class=\"n\">{}</td></tr>",
                esc(g.name(c.src)),
                esc(g.edge_kind_name(c.kind)),
                esc(g.name(c.dst)),
                num(c.flow.round() as u64)
            );
        }
        h.push_str("</tbody></table>");
    }

    // Details
    h.push_str("<h2>5. Finding details</h2>");
    for f in r.findings {
        let s = sev_str(f.def.severity);
        let _ = write!(h, "<div class=\"finding\" id=\"f-{}\"><h3><span class=\"sev {s}\">{s}</span> {}</h3>", esc(f.def.id), esc(f.def.title));
        let _ = write!(h, "<p>{}</p><p><b>Impact.</b> {}</p><p><b>Remediation.</b> {}</p>", esc(f.def.description), esc(f.def.impact), esc(f.def.remediation));
        if !f.def.mitre.is_empty() {
            let _ = write!(h, "<p class=\"muted\">MITRE ATT&amp;CK: {}</p>", esc(&f.def.mitre.join(", ")));
        }
        let lines = item_lines(g, f, r.items_per_finding);
        let more = f.items.len().saturating_sub(lines.len());
        let _ = write!(h, "<div class=\"items\">{}", esc(&lines.join("\n")));
        if more > 0 {
            let _ = write!(h, "\n… and {} more (full list in the CSV export)", num(more as u64));
        }
        h.push_str("</div></div>");
    }
    h.push_str("<p class=\"muted\">Grades: A no exposure · B some exposure · C &gt;5% or a high finding · D &gt;20% or a critical finding · F &gt;50% or three or more critical findings.</p>");
    h.push_str("</main></body></html>");
    h
}

// ----------------------------------------------------------- Markdown

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn render_markdown(r: &ReportInput) -> String {
    let g = r.graph;
    let sm = summary(r);
    let mut m = String::new();
    let _ = writeln!(m, "# {}\n", r.title);
    let _ = writeln!(m, "_Generated {} · snapshot `{}` · {} objects, {} relationships_\n", r.generated_at, r.snapshot_id, num(g.node_count() as u64), num(g.edge_count() as u64));
    let _ = writeln!(m, "## Executive summary\n");
    let _ = writeln!(m, "- **Posture grade: {}** ({})", sm.grade.0, sm.grade.1);
    let _ = writeln!(
        m,
        "- **{:.1}%** of principals ({} of {}) have an attack path to Tier Zero ({} Tier Zero objects)",
        sm.exposure_percent,
        num(r.tier0.exposed_principals),
        num(r.tier0.total_principals),
        num(r.tier0.tier0_nodes)
    );
    let _ = writeln!(m, "- {} findings: {} critical, {} high, {} medium, {} low", r.findings.len(), sm.by_sev[0], sm.by_sev[1], sm.by_sev[2], sm.by_sev[3]);
    if let Some(p) = r.plan.filter(|p| !p.steps.is_empty()) {
        let last = p.steps.last().expect("non-empty");
        let _ = writeln!(m, "- The {}-step remediation plan cuts exposure by {:.1}%", p.steps.len(), last.cumulative_reduction_percent);
    }
    let _ = writeln!(m, "\n## Findings\n\n| Severity | Finding | Category | Items | Fix removes |\n|---|---|---|---:|---:|");
    for f in r.findings {
        let impact = f
            .exposure
            .as_ref()
            .map(|e| format!("{:.1}% ({}){}", e.percent_of_exposed, num(e.principals_cut), target_suffix(e.target)))
            .unwrap_or_else(|| "—".into());
        let _ = writeln!(m, "| {} | {} | {} | {} | {} |", sev_str(f.def.severity), md_cell(f.def.title), md_cell(f.def.category), num(f.items.len() as u64), impact);
    }
    if let Some(p) = r.plan.filter(|p| !p.steps.is_empty()) {
        let _ = writeln!(m, "\n## Remediation plan\n\n| # | Sever | Cuts | Total cut |\n|---:|---|---:|---:|");
        for (i, s) in p.steps.iter().enumerate() {
            let window = if s.needs_window { ", maintenance window" } else { "" };
            let _ = writeln!(m, "| {} | {} ({}{window}) | {} | {:.1}% |", i + 1, md_cell(g.name(s.node)), g.kind_name(s.node), num(s.principals_cut), s.cumulative_reduction_percent);
        }
    }
    if !r.accepted.is_empty() {
        let _ = writeln!(m, "\n### Accepted risks\n\n| Severity | Finding | Items | Reason | Accepted by | Expires |\n|---|---|---:|---|---|---|");
        for a in r.accepted {
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} | {} ({}) | {} |",
                sev_str(a.severity),
                md_cell(&a.title),
                num(a.items as u64),
                md_cell(&a.reason),
                md_cell(&a.accepted_by),
                a.accepted_at,
                a.expires_at.as_deref().unwrap_or("never")
            );
        }
    }
    let _ = writeln!(m, "\n## Finding details");
    for f in r.findings {
        let _ = writeln!(m, "\n### [{}] {}\n\n{}\n\n**Impact.** {}\n\n**Remediation.** {}\n", sev_str(f.def.severity).to_uppercase(), f.def.title, f.def.description, f.def.impact, f.def.remediation);
        if !f.def.mitre.is_empty() {
            let _ = writeln!(m, "MITRE ATT&CK: {}\n", f.def.mitre.join(", "));
        }
        let lines = item_lines(g, f, r.items_per_finding);
        m.push_str("```\n");
        for l in &lines {
            let _ = writeln!(m, "{l}");
        }
        if f.items.len() > lines.len() {
            let _ = writeln!(m, "… and {} more", num((f.items.len() - lines.len()) as u64));
        }
        m.push_str("```\n");
    }
    m
}

// ---------------------------------------------------------------- CSV

fn csv_field(s: &str) -> String {
    // Quote always; neutralise spreadsheet formula injection.
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// One row per finding item.
pub fn render_csv(r: &ReportInput) -> String {
    let g = r.graph;
    let mut c = String::from("finding_id,severity,finding,category,item_type,source,source_kind,relationship,target,target_kind,object_id\n");
    for f in r.findings {
        let head = format!("{},{},{},{}", csv_field(f.def.id), sev_str(f.def.severity), csv_field(f.def.title), csv_field(f.def.category));
        match &f.items {
            Items::Edges(es) => {
                for &(s, d, k) in es {
                    let _ = writeln!(
                        c,
                        "{head},edge,{},{},{},{},{},{}",
                        csv_field(g.name(s)),
                        g.kind(s).as_str(),
                        csv_field(g.edge_kind_name(k)),
                        csv_field(g.name(d)),
                        g.kind(d).as_str(),
                        csv_field(g.oid(s))
                    );
                }
            }
            Items::Nodes(ns) => {
                for &n in ns {
                    let _ = writeln!(c, "{head},node,{},{},,,,{}", csv_field(g.name(n)), g.kind(n).as_str(), csv_field(g.oid(n)));
                }
            }
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades() {
        assert_eq!(grade(0.0, 0, 0).0, 'A');
        assert_eq!(grade(1.0, 0, 0).0, 'B');
        assert_eq!(grade(1.0, 0, 1).0, 'C');
        assert_eq!(grade(1.0, 1, 0).0, 'D');
        assert_eq!(grade(60.0, 0, 0).0, 'F');
    }

    #[test]
    fn escaping() {
        assert_eq!(esc("<a href='x'>&</a>"), "&lt;a href=&#39;x&#39;&gt;&amp;&lt;/a&gt;");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(num(1234567), "1,234,567");
    }
}
