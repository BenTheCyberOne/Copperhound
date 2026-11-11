// Table view of the nodes currently on the canvas (BloodHound's "table view"):
// sortable, filterable, CSV export, extra property columns fetched on demand.
// Rendered inside the bottom dock, which owns the height.

import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { api } from "../api/client";
import type { ColumnInfo, Node, NodeId } from "../api/types";
import { KindBadge } from "../components/KindBadge";
import { asDate, TIME_KEY } from "../components/propertyGroups";
import { readLocal, writeLocal } from "../hooks/localStore";
import { useApp } from "../state/AppContext";
import { cellText, downloadCsv } from "../util/csv";
import { kindShort } from "./kinds";
import type { GraphStore } from "./store";

const PROPS_KEY = "copperhound.canvasTableProps";
const PAGE = 500;
/** objectids per CHQL lookup; `objectid IN [...]` uses the hash index. */
const LOOKUP_CHUNK = 400;

type BaseKey = "kind" | "name" | "objectid" | "tier0" | "owned" | "enabled" | "in" | "out";
const BASE: { key: BaseKey; label: string; num?: boolean; title?: string }[] = [
  { key: "kind", label: "Type" },
  { key: "name", label: "Name" },
  { key: "objectid", label: "Object ID" },
  { key: "tier0", label: "Tier 0" },
  { key: "owned", label: "Owned" },
  { key: "enabled", label: "Enabled" },
  { key: "in", label: "In", num: true, title: "Incoming edges on the canvas" },
  { key: "out", label: "Out", num: true, title: "Outgoing edges on the canvas" },
];
const isBase = (key: string) => BASE.some((b) => b.key === key);

interface Row {
  node: Node;
  in: number;
  out: number;
}

type Sort = { key: string; desc: boolean };

const chqlString = (s: string) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
const chqlProp = (k: string) => (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) ? k : `\`${k.replace(/`/g, "``")}\``);

function baseValue(r: Row, key: BaseKey): unknown {
  if (key === "in") return r.in;
  if (key === "out") return r.out;
  return r.node[key];
}

function compare(a: unknown, b: unknown): number {
  const na = a === null || a === undefined || a === "";
  const nb = b === null || b === undefined || b === "";
  if (na || nb) return na === nb ? 0 : na ? 1 : -1; // blanks last
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(b) - Number(a);
  return cellText(a).localeCompare(cellText(b), undefined, { numeric: true, sensitivity: "base" });
}

function display(key: string, v: unknown): { text: string; title?: string } {
  if (typeof v === "boolean") return { text: v ? "✓" : "" };
  const date = TIME_KEY.test(key) ? asDate(v) : null;
  if (date) return { text: date.toLocaleString(), title: cellText(v) };
  return { text: cellText(v) };
}

/** Fetches raw property values for canvas nodes, keyed by node id. */
function usePropertyValues(store: GraphStore, nodes: Node[], props: string[]) {
  const [values, setValues] = useState<Map<NodeId, Record<string, unknown>>>(new Map());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idsKey = useMemo(() => nodes.map((n) => n.id).join(","), [nodes]);
  const propsKey = props.join("\u0000");

  useEffect(() => {
    if (props.length === 0 || nodes.length === 0) {
      setValues(new Map());
      setError(null);
      return;
    }
    let live = true;
    setLoading(true);
    setError(null);
    (async () => {
      const out = new Map<NodeId, Record<string, unknown>>();
      const oids = [...new Set(nodes.map((n) => n.objectid).filter((o) => o))];
      const ret = props.map((p) => `n.${chqlProp(p)}`).join(", ");
      for (let i = 0; i < oids.length; i += LOOKUP_CHUNK) {
        const chunk = oids.slice(i, i + LOOKUP_CHUNK);
        const query = `MATCH (n) WHERE n.objectid IN [${chunk.map(chqlString).join(",")}] RETURN id(n), ${ret}`;
        // Duplicate objectids can match more nodes than the chunk size.
        const r = await api.query({ query, limit: chunk.length * 4 + 16 });
        if (!live) return;
        for (const row of r.rows ?? []) {
          const rec: Record<string, unknown> = {};
          props.forEach((p, j) => (rec[p] = row[j + 1]));
          out.set(Number(row[0]), rec);
        }
      }
      setValues(out);
    })()
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idsKey, propsKey, store.generation]);

  return { values, loading, error };
}

export function CanvasTable({ tabs, onClose }: { tabs?: ReactNode; onClose: () => void }) {
  const { store, selectedId, select } = useApp();
  const version = useSyncExternalStore(store.subscribe, store.version);
  const g = store.graph;
  const [filter, setFilter] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [sort, setSort] = useState<Sort>({ key: "name", desc: false });
  const [shown, setShown] = useState(PAGE);
  const [props, setProps] = useState<string[]>(() => readLocal<string[]>(PROPS_KEY, []));
  const [columns, setColumns] = useState<ColumnInfo[] | null>(null);
  const [picking, setPicking] = useState(false);
  const selectedRow = useRef<HTMLTableRowElement>(null);

  const rows: Row[] = useMemo(() => {
    const out: Row[] = [];
    g.forEachNode((k, a) => out.push({ node: a.node, in: g.inDegree(k), out: g.outDegree(k) }));
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version]);
  const nodes = useMemo(() => rows.map((r) => r.node), [rows]);
  const { values, loading, error } = usePropertyValues(store, nodes, props);
  const kinds = useMemo(() => [...new Set(rows.map((r) => r.node.kind))].sort(), [rows]);

  const value = (r: Row, key: string): unknown => (isBase(key) ? baseValue(r, key as BaseKey) : values.get(r.node.id)?.[key]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = rows.filter((r) => {
      if (kindFilter && r.node.kind !== kindFilter) return false;
      if (!q) return true;
      if (r.node.name.toLowerCase().includes(q) || r.node.objectid.toLowerCase().includes(q)) return true;
      const extra = values.get(r.node.id);
      return extra ? Object.values(extra).some((v) => cellText(v).toLowerCase().includes(q)) : false;
    });
    const dir = sort.desc ? -1 : 1;
    // Tie-break on node id keeps the order deterministic.
    return list.sort((a, b) => dir * compare(value(a, sort.key), value(b, sort.key)) || a.node.id - b.node.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, filter, kindFilter, sort, values]);

  useEffect(() => setShown(PAGE), [filter, kindFilter, sort]);

  // Keep the selected node's row in view when it is picked on the canvas.
  useEffect(() => {
    if (selectedId === null) return;
    const idx = visible.findIndex((r) => r.node.id === selectedId);
    if (idx >= shown) setShown(Math.ceil((idx + 1) / PAGE) * PAGE);
    window.requestAnimationFrame(() => selectedRow.current?.scrollIntoView({ block: "nearest" }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  const openPicker = () => {
    setPicking((p) => !p);
    if (columns === null)
      api.columns().then(
        (r) => setColumns(r.ready ? (r.columns ?? []) : []),
        () => setColumns([]),
      );
  };
  const setPropList = (next: string[]) => {
    setProps(next);
    writeLocal(PROPS_KEY, next);
  };

  const headers = [
    ...BASE.map((b) => ({ key: b.key as string, label: b.label, num: b.num, title: b.title })),
    ...props.map((p) => ({ key: p, label: p, num: false, title: p })),
  ];

  const exportCsv = () =>
    downloadCsv(
      "copperhound-canvas.csv",
      ["id", ...headers.map((h) => h.key)],
      visible.map((r) => [r.node.id, ...headers.map((h) => value(r, h.key))]),
    );

  const header = (h: (typeof headers)[number]) => {
    const active = sort.key === h.key;
    return (
      <th key={h.key} className={h.num ? "num" : ""} title={h.title} aria-sort={active ? (sort.desc ? "descending" : "ascending") : "none"}>
        <button type="button" className="th-btn" onClick={() => setSort((s) => ({ key: h.key, desc: s.key === h.key ? !s.desc : false }))}>
          {h.label}
          {active ? (sort.desc ? " ▾" : " ▴") : ""}
        </button>
        {!isBase(h.key) && (
          <button
            type="button"
            className="th-remove"
            aria-label={`Remove column ${h.key}`}
            title="Remove column"
            onClick={() => {
              setPropList(props.filter((p) => p !== h.key));
              if (sort.key === h.key) setSort({ key: "name", desc: false });
            }}
          >
            ×
          </button>
        )}
      </th>
    );
  };

  const available = (columns ?? []).filter((c) => !props.includes(c.key)).sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));

  return (
    <section className="canvas-table" aria-label="Canvas nodes table">
      <div className="result-head">
        {tabs ?? <strong>Canvas nodes</strong>}
        <span className="muted">
          {visible.length === rows.length ? `${rows.length}` : `${visible.length} of ${rows.length}`} node{rows.length === 1 ? "" : "s"}
          {loading ? " · loading properties…" : ""}
        </span>
        {error && (
          <span className="error" title={error}>
            Property lookup failed
          </span>
        )}
        <span className="spacer" />
        <input type="search" placeholder="Filter…" aria-label="Filter rows" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <select aria-label="Filter by type" value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
          <option value="">All types</option>
          {kinds.map((k) => (
            <option key={k} value={k}>
              {kindShort(k)}
            </option>
          ))}
        </select>
        <div className="canvas-table-picker">
          <button type="button" className="small" aria-expanded={picking} onClick={openPicker}>
            + Column
          </button>
          {picking && (
            <div className="canvas-table-menu" role="listbox" aria-label="Add property column">
              {columns === null && <div className="muted">Loading…</div>}
              {columns !== null && available.length === 0 && <div className="muted">No more property columns (index may still be building).</div>}
              {available.map((c) => (
                <button
                  key={c.key}
                  type="button"
                  role="option"
                  aria-selected={false}
                  onClick={() => {
                    setPropList([...props, c.key]);
                    setPicking(false);
                  }}
                >
                  <span className="ellipsis">{c.key}</span>
                  <span className="muted num">{c.count.toLocaleString()}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        <button type="button" className="small" onClick={exportCsv} disabled={visible.length === 0}>
          Export CSV
        </button>
        <button type="button" className="icon-btn" aria-label="Close canvas table" onClick={onClose}>
          ×
        </button>
      </div>
      <div className="result-scroll">
        {rows.length === 0 ? (
          <p className="muted canvas-table-empty">No nodes on the canvas.</p>
        ) : (
          <table className="data-table compact">
            <thead>
              <tr>{headers.map(header)}</tr>
            </thead>
            <tbody>
              {visible.slice(0, shown).map((r) => {
                const active = r.node.id === selectedId;
                return (
                  <tr
                    key={r.node.id}
                    ref={active ? selectedRow : undefined}
                    className={`clickable ${active ? "active" : ""}`}
                    tabIndex={0}
                    onClick={() => select(r.node.id)}
                    onDoubleClick={() => store.requestFocus(r.node.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        select(r.node.id);
                        store.requestFocus(r.node.id);
                      }
                    }}
                    title="Click to select · double-click to centre on canvas"
                  >
                    {headers.map((h) => {
                      if (h.key === "kind")
                        return (
                          <td key={h.key}>
                            <KindBadge kind={r.node.kind} />
                          </td>
                        );
                      const d = display(h.key, value(r, h.key));
                      return (
                        <td key={h.key} className={h.num ? "num" : h.key === "objectid" ? "mono" : ""} title={d.title}>
                          {d.text}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {visible.length > shown && (
          <div className="canvas-table-more">
            <button type="button" className="small" onClick={() => setShown(shown + PAGE)}>
              Show {Math.min(PAGE, visible.length - shown)} more ({visible.length - shown} hidden)
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
