import type { SavedQuery } from "../../api/types";
import { Section } from "../../components/Section";
import { useCollapsed } from "../../hooks/useCollapsed";
import { useSession } from "../../state/SessionContext";
import { QueryItem, type RunRequest } from "./QueryLibrary";

const COLLAPSE_KEY = "copperhound.savedQueryCategories";

interface Props {
  saved: SavedQuery[];
  error: string | null;
  filter: string;
  running: boolean;
  onRun: (r: RunRequest) => void;
  onEdit: (q: SavedQuery) => void;
  onDelete: (q: SavedQuery) => void;
}

/** "My queries" from /saved-queries, grouped by their (custom) category. */
export function SavedQueries({ saved, error, filter, running, onRun, onEdit, onDelete }: Props) {
  const editGate = useSession().gate("analyst");
  const { isOpen, toggle } = useCollapsed(COLLAPSE_KEY);
  const f = filter.trim().toLowerCase();
  const visible = saved.filter(
    (q) => !f || [q.name, q.description, q.category, q.query].some((s) => s.toLowerCase().includes(f)),
  );
  const groups = new Map<string, SavedQuery[]>();
  for (const q of [...visible].sort((a, b) => a.name.localeCompare(b.name))) {
    groups.set(q.category, [...(groups.get(q.category) ?? []), q]);
  }

  return (
    <>
      <h3>
        My queries <span className="muted num">{saved.length}</span>
      </h3>
      {error && <p className="error">{error}</p>}
      {saved.length === 0 && !error && (
        <p className="muted small-text">Write a query in the editor and choose “Save…” to keep it here.</p>
      )}
      {[...groups.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([category, qs]) => (
          <Section
            key={category}
            title={
              <>
                {category} <span className="muted num">{qs.length}</span>
              </>
            }
            open={f !== "" || isOpen(category)}
            onToggle={() => toggle(category)}
          >
            <ul className="query-list">
              {qs.map((q) => (
                <QueryItem
                  key={q.id}
                  name={q.name}
                  description={q.description}
                  query={q.query}
                  disabled={running}
                  onRun={() => onRun({ query: q.query, title: q.name })}
                  actions={
                    <>
                      <button type="button" className="icon-btn" aria-label={`Edit ${q.name}`} {...editGate} title={editGate.title ?? "Edit"} onClick={() => onEdit(q)}>
                        ✎
                      </button>
                      <button
                        type="button"
                        className="icon-btn danger"
                        aria-label={`Delete ${q.name}`}
                        disabled={editGate.disabled}
                        title={editGate.title ?? "Delete"}
                        onClick={() => onDelete(q)}
                      >
                        ×
                      </button>
                    </>
                  }
                />
              ))}
            </ul>
          </Section>
        ))}
    </>
  );
}
