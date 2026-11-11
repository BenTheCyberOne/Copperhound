import { useMemo, useState, type ReactNode } from "react";
import type { PrebuiltQuery } from "../../api/types";
import { Section } from "../../components/Section";
import { readLocal, writeLocal } from "../../hooks/localStore";
import { useCollapsed } from "../../hooks/useCollapsed";
import type { RecentQuery } from "./useQueryRunner";

const FAV_KEY = "copperhound.favouriteQueries";
const COLLAPSE_KEY = "copperhound.queryCategories";

export interface RunRequest {
  query: string;
  title?: string;
}

/** One clickable query row, with optional star and extra actions. */
export function QueryItem({
  name,
  description,
  query,
  tags,
  disabled,
  onRun,
  star,
  actions,
}: {
  name: string;
  description?: string;
  query: string;
  tags?: string[];
  disabled: boolean;
  onRun: () => void;
  star?: { on: boolean; toggle: () => void };
  actions?: ReactNode;
}) {
  return (
    <li className="query-row">
      <button type="button" className="query-item" title={query} disabled={disabled} onClick={onRun}>
        <span className="query-name">{name}</span>
        {description && <span className="muted small-text">{description}</span>}
        {tags && tags.length > 0 && (
          <span className="query-tags">
            {tags.map((t) => (
              <span key={t} className="tag small-tag">
                {t}
              </span>
            ))}
          </span>
        )}
      </button>
      <div className="query-row-actions">
        {star && (
          <button
            type="button"
            className={`icon-btn star ${star.on ? "on" : ""}`}
            aria-pressed={star.on}
            aria-label={star.on ? `Remove ${name} from favourites` : `Add ${name} to favourites`}
            onClick={star.toggle}
          >
            {star.on ? "★" : "☆"}
          </button>
        )}
        {actions}
      </div>
    </li>
  );
}

function loadFavourites(): Set<string> {
  const raw = readLocal<unknown>(FAV_KEY, []);
  return new Set(Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : []);
}

const matches = (q: PrebuiltQuery, f: string) =>
  !f ||
  q.name.toLowerCase().includes(f) ||
  q.description.toLowerCase().includes(f) ||
  q.category.toLowerCase().includes(f) ||
  q.tags.some((t) => t.toLowerCase().includes(f));

interface Props {
  prebuilt: PrebuiltQuery[];
  error: string | null;
  recent: RecentQuery[];
  onClearRecent: () => void;
  running: boolean;
  onRun: (r: RunRequest) => void;
  /** Rendered between Recent and the prebuilt categories (My queries). */
  savedSection: ReactNode;
  /** Search text, shared with My queries. */
  filter: string;
  onFilter: (f: string) => void;
}

export function QueryLibrary({ prebuilt, error, recent, onClearRecent, running, onRun, savedSection, filter, onFilter }: Props) {
  const [tags, setTags] = useState<Set<string>>(new Set());
  const [favourites, setFavourites] = useState(loadFavourites);
  const [allTags, setAllTags] = useState(false);
  // Categories start collapsed (there can be ~80 prebuilt queries); favourites and recent start open.
  const { isOpen, toggle } = useCollapsed(COLLAPSE_KEY, false, ["__favourites", "__recent"]);

  const toggleFav = (id: string) =>
    setFavourites((f) => {
      const next = new Set(f);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      writeLocal(FAV_KEY, [...next]);
      return next;
    });

  const tagCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const q of prebuilt) for (const t of q.tags) m.set(t, (m.get(t) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [prebuilt]);

  const f = filter.trim().toLowerCase();
  const visible = prebuilt.filter((q) => matches(q, f) && [...tags].every((t) => q.tags.includes(t)));
  const filtering = f !== "" || tags.size > 0;
  const groups = useMemo(() => {
    const m = new Map<string, PrebuiltQuery[]>();
    for (const q of visible) m.set(q.category, [...(m.get(q.category) ?? []), q]);
    return [...m.entries()];
  }, [visible]);
  const favs = prebuilt.filter((q) => favourites.has(q.id));

  const item = (q: PrebuiltQuery) => (
    <QueryItem
      key={q.id}
      name={q.name}
      description={q.description}
      query={q.query}
      tags={q.tags}
      disabled={running}
      onRun={() => onRun({ query: q.query, title: q.name })}
      star={{ on: favourites.has(q.id), toggle: () => toggleFav(q.id) }}
    />
  );

  const TAG_PREVIEW = 12;
  const shownTags = allTags ? tagCounts : tagCounts.slice(0, TAG_PREVIEW);

  return (
    <>
      <div className="library-filter">
        <input
          type="search"
          placeholder={`Search ${prebuilt.length} queries (name, description, tags)…`}
          aria-label="Search queries"
          value={filter}
          onChange={(e) => onFilter(e.target.value)}
        />
        {tagCounts.length > 0 && (
          <div className="tag-chips" role="group" aria-label="Filter by tag">
            {shownTags.map(([t, n]) => (
              <button
                key={t}
                type="button"
                className={`chip ${tags.has(t) ? "on" : ""}`}
                aria-pressed={tags.has(t)}
                onClick={() =>
                  setTags((s) => {
                    const next = new Set(s);
                    if (next.has(t)) next.delete(t);
                    else next.add(t);
                    return next;
                  })
                }
              >
                {t} <span className="muted">{n}</span>
              </button>
            ))}
            {tagCounts.length > TAG_PREVIEW && (
              <button type="button" className="link-btn" onClick={() => setAllTags((x) => !x)}>
                {allTags ? "fewer" : `+${tagCounts.length - TAG_PREVIEW} more`}
              </button>
            )}
            {tags.size > 0 && (
              <button type="button" className="link-btn" onClick={() => setTags(new Set())}>
                clear tags
              </button>
            )}
          </div>
        )}
      </div>

      {!filtering && favs.length > 0 && (
        <Section
          title={
            <>
              ★ Favourites <span className="muted num">{favs.length}</span>
            </>
          }
          open={isOpen("__favourites")}
          onToggle={() => toggle("__favourites")}
        >
          <ul className="query-list">{favs.map(item)}</ul>
        </Section>
      )}

      {!filtering && recent.length > 0 && (
        <Section
          title={
            <>
              Recent <span className="muted num">{recent.length}</span>
            </>
          }
          open={isOpen("__recent")}
          onToggle={() => toggle("__recent")}
          actions={
            <button type="button" className="link-btn" onClick={onClearRecent}>
              clear
            </button>
          }
        >
          <ul className="query-list">
            {recent.map((r) => (
              <QueryItem
                key={r.query}
                name={r.name ?? r.query}
                description={r.name ? undefined : new Date(r.at).toLocaleString()}
                query={r.query}
                disabled={running}
                onRun={() => onRun({ query: r.query, title: r.name })}
              />
            ))}
          </ul>
        </Section>
      )}

      {savedSection}

      <h3>Prebuilt queries</h3>
      {error && <p className="error">{error}</p>}
      {filtering && groups.length === 0 && <p className="muted small-text">No query matches.</p>}
      {groups.map(([category, qs]) => (
        <Section
          key={category}
          title={
            <>
              {category} <span className="muted num">{qs.length}</span>
            </>
          }
          open={filtering || isOpen(category)}
          onToggle={() => toggle(category)}
        >
          <ul className="query-list">{qs.map(item)}</ul>
        </Section>
      ))}
    </>
  );
}
