import { useMemo, useState } from "react";
import { CATEGORY_ORDER, type Category } from "../graph/kinds";

export interface ChecklistItem {
  name: string;
  category: Category;
  count?: number;
  /** Rendered de-emphasised (e.g. non-traversable edge kinds). */
  muted?: boolean;
  /** Optional colour dot (node kinds). */
  color?: string;
}

interface Props {
  label: string;
  items: ChecklistItem[];
  checked: Set<string>;
  onChange: (next: Set<string>) => void;
  /** Show a text filter above the groups. */
  filterable?: boolean;
  /** Start with groups expanded. */
  open?: boolean;
}

/** Checkbox list grouped by category, with per-category counts and select/clear. */
export function CategoryChecklist({ label, items, checked, onChange, filterable, open = true }: Props) {
  const [filter, setFilter] = useState("");

  const groups = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const visible = items.filter((i) => !f || i.name.toLowerCase().includes(f));
    return CATEGORY_ORDER.map((category) => ({
      category,
      items: visible.filter((i) => i.category === category).sort((a, b) => a.name.localeCompare(b.name)),
    })).filter((g) => g.items.length > 0);
  }, [items, filter]);

  const setMany = (names: string[], on: boolean) => {
    const next = new Set(checked);
    for (const n of names) {
      if (on) next.add(n);
      else next.delete(n);
    }
    onChange(next);
  };

  return (
    <div className="checklist" role="group" aria-label={label}>
      {filterable && (
        <input
          type="search"
          placeholder="Filter kinds…"
          aria-label={`Filter ${label}`}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      )}
      {groups.length === 0 && <p className="muted small-text">Nothing to show.</p>}
      {groups.map((g) => {
        const names = g.items.map((i) => i.name);
        const on = names.filter((n) => checked.has(n)).length;
        const total = g.items.reduce((s, i) => s + (i.count ?? 0), 0);
        return (
          <details key={g.category} className="checklist-group" open={open || filter !== ""}>
            <summary>
              <span className="checklist-cat">{g.category}</span>
              <span className="muted small-text">
                {on}/{names.length}
                {items.some((i) => i.count !== undefined) ? ` · ${total.toLocaleString()}` : ""}
              </span>
              <span className="spacer" />
              <button type="button" className="link-btn" onClick={(e) => {
                  e.preventDefault(); // keep the <details> from toggling
                  setMany(names, true);
                }} disabled={on === names.length}>
                all
              </button>
              <button type="button" className="link-btn" onClick={(e) => {
                  e.preventDefault();
                  setMany(names, false);
                }} disabled={on === 0}>
                none
              </button>
            </summary>
            <div className="checklist-items">
              {g.items.map((i) => (
                <label key={i.name} className="check">
                  <input type="checkbox" checked={checked.has(i.name)} onChange={(e) => setMany([i.name], e.target.checked)} />
                  {i.color && <span className="kind-dot" style={{ ["--kind" as string]: i.color }} />}
                  <span className={`ellipsis ${i.muted ? "muted" : ""}`} title={i.name}>
                    {i.name}
                  </span>
                  {i.count !== undefined && <span className="muted num small-text">{i.count.toLocaleString()}</span>}
                </label>
              ))}
            </div>
          </details>
        );
      })}
    </div>
  );
}
