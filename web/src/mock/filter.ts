// Mock POST /nodes/filter and GET /columns (crates/store/src/{filter.rs,columns.rs}):
// the Filter tree evaluated over the mock nodes with CHQL comparison semantics.

import type { ColumnInfo, ColumnType, Filter, FilterOp, FilterResponse, FilterValue } from "../api/types";
import type { ApiResponse } from "../api/client";
import { nodes, type MockNode } from "./data";
import { publicNode } from "./graph";

const ok = (body: unknown): ApiResponse => ({ status: 200, body });
const fail = (status: number, error: string): ApiResponse => ({ status, body: { error } });

const ATTRS = new Set(["name", "objectid", "kind", "id", "enabled", "tier0", "owned"]);

function lookup(n: MockNode, rawKey: string): unknown {
  const key = rawKey.toLowerCase();
  if (ATTRS.has(key)) return (n as unknown as Record<string, unknown>)[key];
  const entry = Object.entries(n.properties).find(([k]) => k.toLowerCase() === key);
  return entry?.[1] ?? null;
}

type Scalar = string | number | boolean;

function toNum(v: unknown): number | null {
  if (typeof v === "number") return v;
  if (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))) return Number(v);
  return null;
}

function cmpScalar(a: Scalar, op: FilterOp, b: FilterValue): boolean {
  if (op === "in") return Array.isArray(b) && b.some((x) => x !== null && cmpScalar(a, "eq", x));
  if (b === null || Array.isArray(b)) return false;
  const na = toNum(a);
  const nb = toNum(b);
  const numeric = na !== null && nb !== null && typeof a !== "boolean" && typeof b !== "boolean";
  const sa = String(a).toLowerCase();
  const sb = String(b).toLowerCase();
  const order = numeric ? na! - nb! : sa < sb ? -1 : sa > sb ? 1 : 0;
  switch (op) {
    case "eq":
      return order === 0;
    case "ne":
      return order !== 0;
    case "lt":
      return order < 0;
    case "le":
      return order <= 0;
    case "gt":
      return order > 0;
    case "ge":
      return order >= 0;
    case "starts_with":
      return sa.startsWith(sb);
    case "ends_with":
      return sa.endsWith(sb);
    case "contains":
      return sa.includes(sb);
  }
}

const OP_ALIASES: Record<string, FilterOp> = { "=": "eq", "<>": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge" };

class FilterError extends Error {}

function evaluate(f: Filter, n: MockNode): boolean {
  if ("const" in f) return f.const;
  if ("kind" in f) return (Array.isArray(f.kind) ? f.kind : [f.kind]).some((k) => k.toLowerCase() === n.kind.toLowerCase());
  if ("cmp" in f) {
    const op = (OP_ALIASES[f.cmp.op] ?? f.cmp.op) as FilterOp;
    if (!["eq", "ne", "lt", "le", "gt", "ge", "starts_with", "ends_with", "contains", "in"].includes(op)) {
      throw new FilterError(`unknown comparison operator ${String(f.cmp.op)}`);
    }
    const v = lookup(n, f.cmp.key);
    if (v === null || v === undefined) return false;
    const values = Array.isArray(v) ? (v as Scalar[]) : [v as Scalar];
    return values.some((x) => typeof x !== "object" && cmpScalar(x, op, f.cmp.value));
  }
  if ("is_null" in f) {
    const v = lookup(n, f.is_null.key);
    const isNull = v === null || v === undefined;
    return (f.is_null.null ?? true) ? isNull : !isNull;
  }
  if ("truthy" in f) {
    const v = lookup(n, f.truthy);
    if (Array.isArray(v)) return v.length > 0;
    return v !== null && v !== undefined && v !== false && v !== 0 && v !== "";
  }
  if ("and" in f) return f.and.every((x) => evaluate(x, n));
  if ("or" in f) return f.or.some((x) => evaluate(x, n));
  if ("not" in f) return !evaluate(f.not, n);
  throw new FilterError("unknown filter node");
}

export function filterNodes(body: { filter?: Filter; limit?: number; offset?: number }): ApiResponse {
  if (!body.filter) return fail(400, "missing filter");
  const t = performance.now();
  let hits: MockNode[];
  try {
    const filter = body.filter;
    hits = nodes.filter((n) => evaluate(filter, n));
  } catch (e) {
    if (e instanceof FilterError) return fail(400, e.message);
    throw e;
  }
  const filterMs = performance.now() - t;
  const limit = Math.min(body.limit ?? 100, 10000);
  const offset = body.offset ?? 0;
  const res: FilterResponse = {
    total: hits.length,
    offset,
    nodes: hits.slice(offset, offset + limit).map(publicNode),
    filter_ms: Math.round(filterMs * 1000) / 1000,
    elapsed_ms: Math.round((performance.now() - t) * 1000) / 1000,
  };
  return ok(res);
}

function typeOf(v: unknown): ColumnType {
  if (typeof v === "boolean") return "bool";
  if (typeof v === "number") return Number.isInteger(v) ? "int" : "float";
  if (typeof v === "string") return "str";
  if (v === null) return "null";
  return "raw";
}

export function columns(): ApiResponse {
  const byKey = new Map<string, { type: ColumnType; count: number; values: Set<string> }>();
  for (const n of nodes) {
    for (const [k, v] of Object.entries(n.properties)) {
      const key = k.toLowerCase();
      const c = byKey.get(key) ?? { type: typeOf(v), count: 0, values: new Set<string>() };
      if (c.type !== typeOf(v)) c.type = "raw";
      c.count++;
      c.values.add(JSON.stringify(v));
      byKey.set(key, c);
    }
  }
  const cols: ColumnInfo[] = [...byKey.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, c]) => ({
      key,
      type: c.type,
      count: c.count,
      distinct: c.type === "str" ? c.values.size : null,
      eq_index: c.type === "str" && c.values.size <= 4096,
    }));
  return ok({ ready: true, origin: "built", complete: true, columns: cols });
}
