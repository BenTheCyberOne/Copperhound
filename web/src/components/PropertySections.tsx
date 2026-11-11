import { Fragment, useMemo, useState, type ReactNode } from "react";
import { asDate, relativeAge, sectionOf, SECTIONS, type SectionId } from "./propertyGroups";
import { Section } from "./Section";

const LONG = 140;

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v, null, 1);
}

function Value({ v, time }: { v: unknown; time: boolean }) {
  const [expanded, setExpanded] = useState(false);
  if (time) {
    const d = asDate(v);
    if (d) {
      return (
        <>
          <span className="prop-value">{d.toLocaleString()}</span>
          <span className="muted prop-hint" title={formatValue(v)}>
            {relativeAge(d)}
          </span>
        </>
      );
    }
    if (typeof v === "number" && v <= 0) return <span className="prop-value muted">never</span>;
  }
  const text = formatValue(v);
  const long = text.length > LONG || text.includes("\n");
  return (
    <>
      <span className={`prop-value ${typeof v}`}>{long && !expanded ? `${text.slice(0, LONG).replace(/\n/g, " ")}…` : text}</span>
      {long && (
        <button type="button" className="link-btn" onClick={() => setExpanded((x) => !x)} aria-expanded={expanded}>
          {expanded ? "less" : "more"}
        </button>
      )}
    </>
  );
}

type Sort = "key-asc" | "key-desc" | "value";

interface Props {
  properties: Record<string, unknown>;
  adcsObject: boolean;
  isOpen: (id: string) => boolean;
  toggle: (id: string) => void;
  /** Extra content rendered at the top of the Overview section (node fields). */
  overviewExtra: ReactNode;
  /** Rendered between Overview and the remaining sections (edge counts). */
  afterOverview: ReactNode;
}

/** Properties split into Overview / Security / Timestamps / ADCS / Other, filterable and sortable. */
export function PropertySections({ properties, adcsObject, isOpen, toggle, overviewExtra, afterOverview }: Props) {
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<Sort>("key-asc");

  const grouped = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const groups = new Map<SectionId, [string, unknown][]>(SECTIONS.map((s) => [s.id, []]));
    for (const [k, v] of Object.entries(properties)) {
      if (f && !k.toLowerCase().includes(f) && !formatValue(v).toLowerCase().includes(f)) continue;
      groups.get(sectionOf(k, adcsObject))!.push([k, v]);
    }
    const cmp = (a: [string, unknown], b: [string, unknown]) => {
      if (sort === "value") return formatValue(a[1]).localeCompare(formatValue(b[1]), undefined, { numeric: true });
      return a[0].localeCompare(b[0]) * (sort === "key-asc" ? 1 : -1);
    };
    for (const rows of groups.values()) rows.sort(cmp);
    return groups;
  }, [properties, adcsObject, filter, sort]);

  return (
    <div className="props">
      <div className="row gap">
        <input
          type="search"
          className="props-filter"
          placeholder={`Filter ${Object.keys(properties).length} properties…`}
          aria-label="Filter properties"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <select aria-label="Sort properties" value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
          <option value="key-asc">Name A→Z</option>
          <option value="key-desc">Name Z→A</option>
          <option value="value">By value</option>
        </select>
      </div>
      {SECTIONS.map((s) => {
        const rows = grouped.get(s.id)!;
        if (rows.length === 0 && s.id !== "overview") return null;
        return (
          <Fragment key={s.id}>
          <Section
            title={
              <>
                {s.label} <span className="muted num">{rows.length}</span>
              </>
            }
            open={isOpen(`props-${s.id}`) || filter !== ""}
            onToggle={() => toggle(`props-${s.id}`)}
          >
            {s.id === "overview" && overviewExtra}
            {rows.length > 0 && (
              <table className="data-table props-table">
                <tbody>
                  {rows.map(([k, v]) => (
                    <tr key={k}>
                      <td className="prop-key">{k}</td>
                      <td>
                        <Value v={v} time={s.id === "time"} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
          {s.id === "overview" && afterOverview}
          </Fragment>
        );
      })}
    </div>
  );
}
