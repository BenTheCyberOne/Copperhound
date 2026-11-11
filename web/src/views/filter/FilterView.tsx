import { useEffect, useId, useMemo, useState } from "react";
import { ApiError, api, errorMessage } from "../../api/client";
import type { ColumnInfo, Filter, FilterResponse, Node } from "../../api/types";
import { KindBadge } from "../../components/KindBadge";
import { Pager } from "../../components/Pager";
import { EmptyState } from "../../components/StatusView";
import { CATEGORY_ORDER, kindShort } from "../../graph/kinds";
import { readLocal, writeLocal } from "../../hooks/localStore";
import { navigate } from "../../hooks/useRoute";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { downloadCsv } from "../../util/csv";
import {
  BUILTIN_KEYS,
  BuildError,
  buildFilter,
  bumpIds,
  EXAMPLES,
  newGroup,
  newPredicate,
  OP_LABEL,
  UI_OPS,
  VALUELESS,
  type BuilderState,
  type Group,
  type Predicate,
  type UiOp,
} from "./model";

const STORE_KEY = "copperhound.objectFilter";
const PAGE_SIZES = [50, 100, 500, 1000];
const EXPORT_MAX = 50_000;
const EXPORT_PAGE = 10_000;
const COLUMNS_RETRY_MS = 5000;
/** Canvas loads use /subgraph, which takes at most 5000 ids. */
const CANVAS_MAX = 5000;

function initialState(): BuilderState {
  const saved = readLocal<BuilderState | null>(STORE_KEY, null);
  if (saved && Array.isArray(saved.kinds) && saved.root?.type === "group") {
    bumpIds(saved.root);
    return saved;
  }
  return { kinds: [], root: newGroup("and", [newPredicate()]) };
}

function KindPicker({ selected, onChange }: { selected: string[]; onChange: (k: string[]) => void }) {
  const { nodeKinds } = useCatalog();
  const present = nodeKinds.filter((k) => k.count > 0 || selected.includes(k.name));
  const groups = CATEGORY_ORDER.map((c) => ({ c, items: present.filter((k) => k.category === c) })).filter((g) => g.items.length > 0);
  const toggle = (name: string) => onChange(selected.includes(name) ? selected.filter((k) => k !== name) : [...selected, name]);
  return (
    <fieldset className="kind-picker">
      <legend>
        Kinds <span className="muted small-text">{selected.length === 0 ? "(any)" : `(${selected.length} selected)`}</span>
        {selected.length > 0 && (
          <button type="button" className="link-btn" onClick={() => onChange([])}>
            clear
          </button>
        )}
      </legend>
      {groups.length === 0 && <span className="muted small-text">No graph loaded.</span>}
      {groups.map((g) => (
        <div key={g.c} className="kind-picker-group">
          <span className="edge-group-label">{g.c}</span>
          <div className="tag-chips">
            {g.items.map((k) => (
              <button
                key={k.name}
                type="button"
                className={`chip ${selected.includes(k.name) ? "on" : ""}`}
                aria-pressed={selected.includes(k.name)}
                onClick={() => toggle(k.name)}
                title={`${k.count.toLocaleString()} ${k.name} objects`}
              >
                <KindBadge kind={k.name} dotOnly /> {kindShort(k.name)} <span className="muted num">{k.count.toLocaleString()}</span>
              </button>
            ))}
          </div>
        </div>
      ))}
    </fieldset>
  );
}

function PredicateRow({ p, listId, onChange, onRemove }: { p: Predicate; listId: string; onChange: (p: Predicate) => void; onRemove: () => void }) {
  const valueless = VALUELESS.has(p.op);
  return (
    <div className="pred-row">
      <input
        className="pred-key"
        aria-label="Property"
        list={listId}
        value={p.key}
        placeholder="property, e.g. hasspn"
        spellCheck={false}
        onChange={(e) => onChange({ ...p, key: e.target.value })}
      />
      <select aria-label="Operator" value={p.op} onChange={(e) => onChange({ ...p, op: e.target.value as UiOp })}>
        {UI_OPS.map((op) => (
          <option key={op} value={op}>
            {OP_LABEL[op]}
          </option>
        ))}
      </select>
      {!valueless && (
        <input
          className="pred-value"
          aria-label="Value"
          value={p.value}
          placeholder={p.op === "in" ? "a, b, c" : "value or “90 days ago”"}
          spellCheck={false}
          onChange={(e) => onChange({ ...p, value: e.target.value })}
        />
      )}
      <button type="button" className="icon-btn" aria-label="Remove condition" onClick={onRemove}>
        ×
      </button>
    </div>
  );
}

function GroupEditor({
  g,
  listId,
  depth,
  onChange,
  onRemove,
}: {
  g: Group;
  listId: string;
  depth: number;
  onChange: (g: Group) => void;
  onRemove?: () => void;
}) {
  const setItem = (i: number, it: Predicate | Group) => onChange({ ...g, items: g.items.map((x, j) => (j === i ? it : x)) });
  const removeItem = (i: number) => onChange({ ...g, items: g.items.filter((_, j) => j !== i) });
  return (
    <div className={`filter-group depth-${Math.min(depth, 3)}`} role="group" aria-label={depth === 0 ? "Conditions" : "Condition group"}>
      <div className="row gap wrap filter-group-head">
        {g.negate && <span className="tag warn">NOT</span>}
        <span className="muted small-text">Match</span>
        <div className="seg" role="radiogroup" aria-label="Combine conditions">
          {(["and", "or"] as const).map((m) => (
            <button key={m} type="button" role="radio" aria-checked={g.mode === m} className={g.mode === m ? "on" : ""} onClick={() => onChange({ ...g, mode: m })}>
              {m === "and" ? "all (AND)" : "any (OR)"}
            </button>
          ))}
        </div>
        <span className="muted small-text">of these</span>
        <label className="toggle small-text">
          <input type="checkbox" checked={g.negate} onChange={(e) => onChange({ ...g, negate: e.target.checked })} />
          negate
        </label>
        <span className="spacer" />
        {onRemove && (
          <button type="button" className="small" onClick={onRemove}>
            Remove group
          </button>
        )}
      </div>
      {g.items.length === 0 && <p className="muted small-text">No conditions: matches everything.</p>}
      {g.items.map((it, i) => (
        <div key={it.id} className="filter-item">
          {i > 0 && <span className="filter-joiner">{g.mode.toUpperCase()}</span>}
          {it.type === "pred" ? (
            <PredicateRow p={it} listId={listId} onChange={(p) => setItem(i, p)} onRemove={() => removeItem(i)} />
          ) : (
            <GroupEditor g={it} listId={listId} depth={depth + 1} onChange={(x) => setItem(i, x)} onRemove={() => removeItem(i)} />
          )}
        </div>
      ))}
      <div className="row gap">
        <button type="button" className="small" onClick={() => onChange({ ...g, items: [...g.items, newPredicate()] })}>
          + Condition
        </button>
        {depth < 3 && (
          <button
            type="button"
            className="small"
            onClick={() => onChange({ ...g, items: [...g.items, newGroup(g.mode === "and" ? "or" : "and", [newPredicate()])] })}
          >
            + Group
          </button>
        )}
      </div>
    </div>
  );
}

/** Kinds for which "enabled" is meaningful (groups etc. are never "enabled"). */
const HAS_ENABLED = new Set(["User", "Computer", "AZUser", "AZServicePrincipal", "AZDevice"]);

function flagTags(n: Node) {
  return (
    <span className="tags">
      {!n.enabled && HAS_ENABLED.has(n.kind) && <span className="tag off">disabled</span>}
      {n.tier0 && <span className="tag tier0">T0</span>}
      {n.owned && <span className="tag owned">owned</span>}
    </span>
  );
}

/** #/filter: build a property filter visually and page through the matching objects. */
export function FilterView() {
  const { loadResult, select, store, notify, track } = useApp();
  const { generation } = useCatalog();
  const listId = useId();
  const [state, setState] = useState<BuilderState>(initialState);
  const [columns, setColumns] = useState<ColumnInfo[]>([]);
  const [columnsReady, setColumnsReady] = useState<boolean | null>(null);
  const [limit, setLimit] = useState(100);
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState<FilterResponse | null>(null);
  const [ranFilter, setRanFilter] = useState<Filter | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => writeLocal(STORE_KEY, state), [state]);

  // Property key suggestions; the columns build in the background after a graph load.
  useEffect(() => {
    let live = true;
    let timer = 0;
    const load = () =>
      api.columns().then(
        (r) => {
          if (!live) return;
          setColumnsReady(r.ready);
          if (r.ready) setColumns(r.columns ?? []);
          else timer = window.setTimeout(load, COLUMNS_RETRY_MS);
        },
        () => live && setColumnsReady(false),
      );
    void load();
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [generation]);

  const built = useMemo((): { filter: Filter | null; error: string | null } => {
    try {
      return { filter: buildFilter(state, columns), error: null };
    } catch (e) {
      if (e instanceof BuildError) return { filter: null, error: e.message };
      throw e;
    }
  }, [state, columns]);

  const run = async (filter: Filter, off: number, lim = limit) => {
    setRunning(true);
    setError(null);
    try {
      const r = await track(api.filterNodes({ filter, limit: lim, offset: off }));
      setResult(r);
      setRanFilter(filter);
      setOffset(off);
    } catch (e) {
      setError(e instanceof ApiError && e.status === 409 ? "No graph is loaded yet." : errorMessage(e));
    } finally {
      setRunning(false);
    }
  };

  const open = (n: Node) => {
    navigate("explore");
    if (store.has(n.id)) select(n.id);
    else loadResult({ nodes: [n], edges: [], truncated: false, elapsed_ms: 0 }, { forceMerge: true, select: n.id });
  };

  const showPage = async () => {
    if (!result) return;
    try {
      const ids = result.nodes.map((n) => n.id).slice(0, CANVAS_MAX);
      const g = await track(api.subgraph(ids));
      loadResult(g);
      navigate("explore");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const exportCsv = async () => {
    if (!ranFilter || !result) return;
    try {
      const rows: Node[] = [];
      for (let off = 0; off < Math.min(result.total, EXPORT_MAX); off += EXPORT_PAGE) {
        rows.push(...(await track(api.filterNodes({ filter: ranFilter, limit: EXPORT_PAGE, offset: off }))).nodes);
      }
      downloadCsv(
        "copperhound-objects.csv",
        ["name", "kind", "objectid", "enabled", "tier0", "owned"],
        rows.map((n) => [n.name, n.kind, n.objectid, n.enabled, n.tier0, n.owned]),
      );
      if (result.total > EXPORT_MAX) notify(`Exported the first ${EXPORT_MAX.toLocaleString()} of ${result.total.toLocaleString()} objects.`, "warn");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  const keyOptions = useMemo(() => {
    const seen = new Set(BUILTIN_KEYS.map((k) => k.key));
    return [
      ...BUILTIN_KEYS.map((k) => ({ key: k.key, label: `${k.type} · node attribute` })),
      ...columns
        .filter((c) => !seen.has(c.key.toLowerCase()))
        .map((c) => ({ key: c.key, label: `${c.type} · ${c.count.toLocaleString()} objects${c.distinct !== null ? ` · ${c.distinct.toLocaleString()} distinct` : ""}` })),
    ];
  }, [columns]);

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Object filter</h1>
          <p className="muted">
            Find objects by kind and properties without writing a query. Runs on the server's typed property columns, so it is
            fast even on very large graphs.
          </p>
        </div>
        <div className="head-actions">
          <label className="inline-field">
            Examples
            <select
              value=""
              onChange={(e) => {
                const ex = EXAMPLES[Number(e.target.value)];
                if (ex) setState(ex.state());
              }}
            >
              <option value="">Choose…</option>
              {EXAMPLES.map((ex, i) => (
                <option key={ex.label} value={i}>
                  {ex.label}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={() => setState({ kinds: [], root: newGroup("and", [newPredicate()]) })}>
            Reset
          </button>
        </div>
      </header>

      <section className="card form-stack">
        <KindPicker selected={state.kinds} onChange={(kinds) => setState((s) => ({ ...s, kinds }))} />
        <GroupEditor g={state.root} listId={listId} depth={0} onChange={(root) => setState((s) => ({ ...s, root }))} />
        <datalist id={listId}>
          {keyOptions.map((k) => (
            <option key={k.key} value={k.key} label={k.label} />
          ))}
        </datalist>
        {columnsReady === false && (
          <p className="muted small-text">
            Property columns are still being built after the last graph load: suggestions are limited to node attributes for
            now (filtering works, it may just be slower).
          </p>
        )}
        <p className="muted small-text">
          Strings compare case-insensitively, numeric strings compare as numbers, and a list property matches if any element
          does. Timestamps are Unix seconds; type e.g. <code>90 days ago</code> as a value.
        </p>
        {built.error && <p className="warn-text small-text">{built.error}</p>}
        <div className="row gap wrap">
          <button type="button" className="primary" disabled={!built.filter || running} onClick={() => built.filter && void run(built.filter, 0)}>
            {running ? "Filtering…" : "Find objects"}
          </button>
          <label className="inline-field">
            Page size
            <select
              value={limit}
              onChange={(e) => {
                const l = Number(e.target.value);
                setLimit(l);
                if (ranFilter) void run(ranFilter, 0, l);
              }}
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <span className="spacer" />
          {built.filter && (
            <details className="filter-json">
              <summary className="small-text">Filter JSON</summary>
              <pre className="code-block">{JSON.stringify({ filter: built.filter }, null, 2)}</pre>
            </details>
          )}
        </div>
      </section>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <section className="card">
          <div className="section-head">
            <h2>
              {result.total.toLocaleString()} {result.total === 1 ? "match" : "matches"}{" "}
              <span className="muted small-text">
                filter {result.filter_ms.toFixed(1)} ms · total {result.elapsed_ms.toFixed(1)} ms
              </span>
            </h2>
            <div className="head-actions">
              <Pager offset={offset} total={result.total} page={limit} onChange={(o) => ranFilter && void run(ranFilter, o)} />
              <button type="button" className="small" disabled={result.nodes.length === 0} onClick={() => void showPage()} title="Load this page (and the edges among it) onto the canvas">
                Show page in graph
              </button>
              <button type="button" className="small" disabled={result.total === 0} onClick={() => void exportCsv()}>
                Export CSV
              </button>
            </div>
          </div>
          {result.nodes.length === 0 ? (
            <EmptyState title="No objects match">Loosen a condition or remove a kind.</EmptyState>
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Kind</th>
                    <th>Object ID</th>
                    <th>Flags</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {result.nodes.map((n) => (
                    <tr key={n.id}>
                      <td className="cell-name">{n.name}</td>
                      <td>
                        <KindBadge kind={n.kind} />
                      </td>
                      <td>
                        <code className="small-text break">{n.objectid}</code>
                      </td>
                      <td>{flagTags(n)}</td>
                      <td className="row-actions">
                        <button type="button" className="small" onClick={() => open(n)}>
                          Open
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
