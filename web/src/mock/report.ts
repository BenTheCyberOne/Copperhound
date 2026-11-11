// Mock of GET /report: a self-contained assessment in HTML, Markdown or CSV.

import { findingDetail, findingsResponse, remediationPlan, state } from "./analysis";
import { exposureReport, tier0Targets } from "./exposure";

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const csvCell = (v: string | number) => (/[",\r\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));

interface Opts {
  title: string;
  planSteps: number;
  items: number;
}

function gather(o: Opts) {
  const findings = findingsResponse();
  const exposure = exposureReport(tier0Targets(), 10);
  const plan = o.planSteps > 0 ? remediationPlan({ steps: o.planSteps }) : null;
  const details = findings.findings.map((f) => findingDetail(f.id, 0, o.items)!);
  return { findings, exposure, plan, details };
}

export function renderReport(format: "html" | "md" | "csv", o: Opts): { text: string; type: string } {
  const { findings, exposure, plan, details } = gather(o);
  const generated = new Date().toISOString();
  const label = (i: (typeof details)[number]["items"][number]) =>
    "node" in i ? `${i.node.name} (${i.node.kind})` : `${i.src.name} -[${i.kind}]-> ${i.dst.name}`;

  if (format === "csv") {
    const rows = [["finding_id", "severity", "title", "item"]];
    for (const d of details) for (const i of d.items) rows.push([d.id, d.severity, d.title, label(i)]);
    return { text: rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n", type: "text/csv" };
  }

  if (format === "md") {
    const lines = [
      `# ${o.title}`,
      "",
      `Generated ${generated} · snapshot \`${state.snapshotId}\``,
      "",
      "## Summary",
      "",
      `- Tier Zero objects: ${exposure.tier0_nodes}`,
      `- Principals with a path to Tier Zero: ${exposure.exposed_principals}`,
      `- Findings: ${findings.summary.critical} critical, ${findings.summary.high} high, ${findings.summary.medium} medium, ${findings.summary.low} low`,
      "",
      "## Findings",
      "",
    ];
    for (const d of details) {
      lines.push(`### [${d.severity.toUpperCase()}] ${d.title}`, "", d.description, "", `**Remediation:** ${d.remediation.replace(/\n+/g, " ")}`, "");
      for (const i of d.items) lines.push(`- ${label(i)}`);
      if (d.total > d.items.length) lines.push(`- … ${d.total - d.items.length} more`);
      lines.push("");
    }
    if (plan) {
      lines.push("## Remediation plan", "");
      plan.steps.forEach((s, i) =>
        lines.push(`${i + 1}. Remove ${s.edge_count} edge(s) from ${s.node.name} — cuts ${s.principals_cut}, total ${s.cumulative_reduction_percent}%`),
      );
    }
    return { text: lines.join("\n") + "\n", type: "text/markdown" };
  }

  const sevColor: Record<string, string> = { critical: "#be123c", high: "#c2410c", medium: "#a16207", low: "#1d4ed8" };
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(o.title)}</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;color:#1c1830;max-width:900px;margin:32px auto;padding:0 20px}
h1{margin-bottom:0}h2{border-bottom:2px solid #a4502a;padding-bottom:4px;margin-top:32px}
.meta{color:#625c7a}.cards{display:flex;gap:12px}.card{flex:1;border:1px solid #dcd8e8;border-radius:8px;padding:10px}
.card b{font-size:22px;display:block}.sev{color:#fff;border-radius:999px;padding:1px 8px;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:12px}td,th{border-bottom:1px solid #eee;padding:3px 6px;text-align:left}
@media print{body{margin:0}h2{break-after:avoid}}
</style></head><body>
<h1>${esc(o.title)}</h1><p class="meta">Generated ${generated} · snapshot ${esc(state.snapshotId)} · CopperHound (mock data)</p>
<h2>Summary</h2><div class="cards">
<div class="card"><b>${exposure.tier0_nodes}</b>Tier Zero objects</div>
<div class="card"><b>${exposure.exposed_principals}</b>principals with a path</div>
${(["critical", "high", "medium", "low"] as const).map((s) => `<div class="card"><b style="color:${sevColor[s]}">${findings.summary[s]}</b>${s}</div>`).join("")}
</div>
<h2>Findings</h2>
${details
  .map(
    (d) => `<h3><span class="sev" style="background:${sevColor[d.severity]}">${d.severity}</span> ${esc(d.title)}</h3>
<p>${esc(d.description)}</p><p><b>Impact:</b> ${esc(d.impact)}</p><p><b>Remediation:</b> ${esc(d.remediation).replace(/\n/g, "<br>")}</p>
<table><tbody>${d.items.map((i) => `<tr><td>${esc(label(i))}</td></tr>`).join("")}${d.total > d.items.length ? `<tr><td>… ${d.total - d.items.length} more</td></tr>` : ""}</tbody></table>`,
  )
  .join("\n")}
${
  plan
    ? `<h2>Remediation plan</h2><table><thead><tr><th>#</th><th>Object</th><th>Edges</th><th>Cut</th><th>Total reduction</th></tr></thead><tbody>${plan.steps
        .map(
          (s, i) =>
            `<tr><td>${i + 1}</td><td>${esc(s.node.name)}</td><td>${s.edges.map((e) => esc(`${e.kind} → ${e.dst.name}`)).join("<br>")}</td><td>${s.principals_cut}</td><td>${s.cumulative_reduction_percent}%</td></tr>`,
        )
        .join("")}</tbody></table>`
    : ""
}
</body></html>`;
  return { text: html, type: "text/html" };
}
