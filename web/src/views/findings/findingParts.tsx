import type { Severity } from "../../api/types";
import { pctText } from "../../util/format";

export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/** Severity pill: colour plus text, never colour alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev-badge sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}

/** MITRE ATT&CK technique chips linking to the public technique pages. */
export function MitreChips({ ids }: { ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <span className="mitre-chips">
      {ids.map((id) => (
        <a
          key={id}
          className="chip mitre"
          href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`}
          target="_blank"
          rel="noreferrer noopener"
          title={`MITRE ATT&CK ${id}`}
          onClick={(e) => e.stopPropagation()}
        >
          {id}
        </a>
      ))}
    </span>
  );
}

/**
 * Renders plain server text readably: blank lines separate paragraphs, lines that
 * start with "-", "*" or "1." become list items.
 */
export function RichText({ text }: { text: string }) {
  const blocks = text.trim().split(/\n\s*\n/);
  return (
    <div className="rich-text">
      {blocks.map((block, i) => {
        const lines = block.split("\n").map((l) => l.trim()).filter(Boolean);
        const bullet = lines.every((l) => /^[-*•]\s+/.test(l));
        const numbered = lines.every((l) => /^\d+[.)]\s+/.test(l));
        if (lines.length > 0 && (bullet || numbered)) {
          const items = lines.map((l) => l.replace(/^([-*•]|\d+[.)])\s+/, ""));
          const List = numbered ? "ol" : "ul";
          return (
            <List key={i}>
              {items.map((it, j) => (
                <li key={j}>{it}</li>
              ))}
            </List>
          );
        }
        return <p key={i}>{lines.join(" ")}</p>;
      })}
    </div>
  );
}

/** "fixing removes N principals' paths" meter for edge findings. */
export function ImpactBar({ cut, percent, target = "Tier Zero" }: { cut: number; percent: number; target?: string }) {
  const other = target !== "Tier Zero";
  if (cut === 0) return <span className="muted small-text">no principal loses its path{other ? ` to ${target}` : ""}</span>;
  return (
    <div className="impact" title={`Fixing removes ${cut.toLocaleString()} principals' paths to ${target}, ${pctText(percent)} of exposure`}>
      <div className="impact-track" role="presentation">
        <div className="impact-fill" style={{ width: `${Math.min(100, Math.max(percent, percent > 0 ? 2 : 0))}%` }} />
      </div>
      <span className="small-text">
        −{cut.toLocaleString()} <span className="muted">({pctText(percent)}){other ? ` to ${target}` : ""}</span>
      </span>
    </div>
  );
}
