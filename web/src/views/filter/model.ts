// Visual filter builder model and its translation to the /nodes/filter Filter JSON.

import type { ColumnInfo, ColumnType, Filter, FilterOp, FilterScalar } from "../../api/types";

/** Ops offered in the UI: the API comparison ops plus null / truthiness tests. */
export type UiOp = FilterOp | "is_null" | "not_null" | "truthy" | "falsy";

export const OP_LABEL: Record<UiOp, string> = {
  eq: "=",
  ne: "≠",
  lt: "<",
  le: "≤",
  gt: ">",
  ge: "≥",
  starts_with: "starts with",
  ends_with: "ends with",
  contains: "contains",
  in: "is one of",
  is_null: "is null / absent",
  not_null: "is present",
  truthy: "is true / non-empty",
  falsy: "is false / empty",
};

export const UI_OPS = Object.keys(OP_LABEL) as UiOp[];
export const VALUELESS = new Set<UiOp>(["is_null", "not_null", "truthy", "falsy"]);

export interface Predicate {
  id: number;
  type: "pred";
  key: string;
  op: UiOp;
  value: string;
}

export interface Group {
  id: number;
  type: "group";
  mode: "and" | "or";
  negate: boolean;
  items: (Predicate | Group)[];
}

export interface BuilderState {
  kinds: string[];
  root: Group;
}

let seq = 1;
export const nextId = () => ++seq;

/** Ids restored from storage must not collide with new ones. */
export function bumpIds(g: Group): void {
  seq = Math.max(seq, g.id);
  for (const it of g.items) {
    seq = Math.max(seq, it.id);
    if (it.type === "group") bumpIds(it);
  }
}

export const newPredicate = (key = "", op: UiOp = "eq", value = ""): Predicate => ({ id: nextId(), type: "pred", key, op, value });
export const newGroup = (mode: "and" | "or" = "and", items: (Predicate | Group)[] = []): Group => ({
  id: nextId(),
  type: "group",
  mode,
  negate: false,
  items,
});

/** Node attributes every node has (fast path on the server). */
export const BUILTIN_KEYS: { key: string; type: ColumnType }[] = [
  { key: "name", type: "str" },
  { key: "objectid", type: "str" },
  { key: "enabled", type: "bool" },
  { key: "tier0", type: "bool" },
  { key: "owned", type: "bool" },
  { key: "admincount", type: "bool" },
  { key: "highvalue", type: "bool" },
  { key: "unconstraineddelegation", type: "bool" },
  { key: "dontreqpreauth", type: "bool" },
  { key: "hasspn", type: "bool" },
];

export class BuildError extends Error {}

const DAYS_AGO = /^(\d+(?:\.\d+)?)\s*d(?:ays?)?\s+ago$/i;

/** Typed value for a key: numbers for numeric columns, booleans for bool columns; "90 days ago" → epoch seconds. */
export function parseValue(raw: string, type: ColumnType | undefined): FilterScalar {
  const v = raw.trim();
  const ago = DAYS_AGO.exec(v);
  if (ago) return Math.floor(Date.now() / 1000 - Number(ago[1]) * 86400);
  if (v.toLowerCase() === "null") return null;
  if (type === "bool" || (type === undefined && /^(true|false)$/i.test(v))) {
    if (/^true$/i.test(v)) return true;
    if (/^false$/i.test(v)) return false;
    throw new BuildError(`“${v}” is not true or false`);
  }
  if ((type === "int" || type === "float") && v !== "" && !Number.isNaN(Number(v))) return Number(v);
  return v;
}

function predicateFilter(p: Predicate, types: Map<string, ColumnType>): Filter {
  const key = p.key.trim();
  if (!key) throw new BuildError("A condition has no property");
  switch (p.op) {
    case "is_null":
      return { is_null: { key, null: true } };
    case "not_null":
      return { is_null: { key, null: false } };
    case "truthy":
      return { truthy: key };
    case "falsy":
      return { not: { truthy: key } };
    default: {
      const type = types.get(key.toLowerCase());
      if (p.op === "in") {
        const values = p.value
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
          .map((s) => parseValue(s, type));
        if (values.length === 0) throw new BuildError(`“${key} is one of” needs comma-separated values`);
        return { cmp: { key, op: "in", value: values } };
      }
      if (p.value.trim() === "") throw new BuildError(`“${key} ${OP_LABEL[p.op]}” needs a value`);
      return { cmp: { key, op: p.op, value: parseValue(p.value, type) } };
    }
  }
}

function groupFilter(g: Group, types: Map<string, ColumnType>): Filter | null {
  const parts = g.items.map((it) => (it.type === "group" ? groupFilter(it, types) : predicateFilter(it, types))).filter((f): f is Filter => f !== null);
  if (parts.length === 0) return null;
  const inner: Filter = parts.length === 1 ? parts[0]! : g.mode === "and" ? { and: parts } : { or: parts };
  return g.negate ? { not: inner } : inner;
}

/** The Filter for the builder state; `{"const": true}` when nothing is set (all nodes). */
export function buildFilter(s: BuilderState, columns: ColumnInfo[]): Filter {
  const types = new Map<string, ColumnType>([...BUILTIN_KEYS.map((k) => [k.key, k.type] as const), ...columns.map((c) => [c.key.toLowerCase(), c.type] as const)]);
  const parts: Filter[] = [];
  if (s.kinds.length > 0) parts.push({ kind: s.kinds.length === 1 ? s.kinds[0]! : s.kinds });
  const root = groupFilter(s.root, types);
  if (root) parts.push(root);
  if (parts.length === 0) return { const: true };
  return parts.length === 1 ? parts[0]! : { and: parts };
}

export const EXAMPLES: { label: string; state: () => BuilderState }[] = [
  {
    label: "Kerberoastable users",
    state: () => ({
      kinds: ["User"],
      root: newGroup("and", [newPredicate("enabled", "truthy"), newPredicate("hasspn", "truthy"), newPredicate("tier0", "falsy")]),
    }),
  },
  {
    label: "AS-REP roastable",
    state: () => ({ kinds: ["User"], root: newGroup("and", [newPredicate("enabled", "truthy"), newPredicate("dontreqpreauth", "truthy")]) }),
  },
  {
    label: "Stale enabled computers (90 days)",
    state: () => ({
      kinds: ["Computer"],
      root: newGroup("and", [newPredicate("enabled", "truthy"), newPredicate("lastlogontimestamp", "lt", "90 days ago")]),
    }),
  },
  {
    label: "Unconstrained delegation (non Tier Zero)",
    state: () => ({
      kinds: ["User", "Computer"],
      root: newGroup("and", [newPredicate("unconstraineddelegation", "truthy"), newPredicate("tier0", "falsy")]),
    }),
  },
];
