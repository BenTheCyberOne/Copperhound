// A small CHQL interpreter for mock mode. It covers the subset documented in
// docs/API.md well enough to demo the Queries tab; the real engine lives in the backend.

import type { Edge, GraphResult, NodeId } from "../api/types";
import { nodes, type MockNode } from "./data";
import { allShortestPathEdges, edgeAllowed, inAdj, outAdj, resultFrom, shortestPath } from "./graph";

export class ChqlError extends Error {
  constructor(
    message: string,
    readonly position: number | null,
    readonly code: "syntax" | "semantic" = "syntax",
  ) {
    super(message);
  }
}

const DAY = 86400;

// ---------------------------------------------------------------------------
// Lexer

type TokKind = "ident" | "string" | "number" | "punct" | "eof";
interface Token {
  kind: TokKind;
  text: string;
  pos: number;
}

const PUNCT = ["<>", "<=", ">=", "..", "(", ")", "[", "]", "{", "}", ":", ",", ".", "|", "*", "-", ">", "<", "="];

function lex(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "'" || c === '"') {
      const start = i++;
      let text = "";
      while (i < src.length && src[i] !== c) {
        if (src[i] === "\\" && i + 1 < src.length) i++;
        text += src[i++];
      }
      if (i >= src.length) throw new ChqlError("unterminated string literal", start);
      i++;
      out.push({ kind: "string", text, pos: start });
      continue;
    }
    if (/[0-9]/.test(c)) {
      const m = /^[0-9]+(\.[0-9]+)?/.exec(src.slice(i))!;
      out.push({ kind: "number", text: m[0], pos: i });
      i += m[0].length;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i))!;
      out.push({ kind: "ident", text: m[0], pos: i });
      i += m[0].length;
      continue;
    }
    const p = PUNCT.find((x) => src.startsWith(x, i));
    if (!p) throw new ChqlError(`unexpected character '${c}'`, i);
    out.push({ kind: "punct", text: p, pos: i });
    i += p.length;
  }
  out.push({ kind: "eof", text: "", pos: src.length });
  return out;
}

// ---------------------------------------------------------------------------
// AST

type Literal = string | number | boolean | null;
interface NodePat {
  v: string | null;
  labels: string[];
  props: [string, Literal][];
}
interface RelPat {
  v: string | null;
  kinds: string[];
  reverse: boolean;
  min: number;
  max: number;
}
type Expr =
  | { t: "lit"; value: Literal | Literal[] }
  | { t: "prop"; v: string; prop: string }
  | { t: "label"; v: string; label: string }
  | { t: "var"; v: string }
  | { t: "not"; e: Expr }
  | { t: "bin"; op: string; a: Expr; b: Expr }
  | { t: "isnull"; e: Expr; negate: boolean };
type Item = { t: "all" } | { t: "count"; v: string } | { t: "var"; v: string } | { t: "prop"; v: string; prop: string };
interface Query {
  pathVar: string | null;
  pathFn: "shortestPath" | "allShortestPaths" | null;
  nodes: NodePat[];
  rels: RelPat[];
  where: Expr | null;
  items: Item[];
  limit: number | null;
}

// ---------------------------------------------------------------------------
// Parser

class Parser {
  private i = 0;
  constructor(private readonly toks: Token[]) {}

  private peek(offset = 0): Token {
    return this.toks[Math.min(this.i + offset, this.toks.length - 1)]!;
  }
  private next(): Token {
    return this.toks[this.i++]!;
  }
  private isKw(kw: string, offset = 0): boolean {
    const t = this.peek(offset);
    return t.kind === "ident" && t.text.toUpperCase() === kw;
  }
  private isP(p: string): boolean {
    const t = this.peek();
    return t.kind === "punct" && t.text === p;
  }
  private fail(msg: string): never {
    const t = this.peek();
    throw new ChqlError(`${msg}, found ${t.kind === "eof" ? "end of query" : `'${t.text}'`}`, t.pos);
  }
  private kw(kw: string): void {
    if (!this.isKw(kw)) this.fail(`expected ${kw}`);
    this.i++;
  }
  private p(p: string): void {
    if (!this.isP(p)) this.fail(`expected '${p}'`);
    this.i++;
  }
  private ident(what = "identifier"): string {
    if (this.peek().kind !== "ident") this.fail(`expected ${what}`);
    return this.next().text;
  }
  private int(): number {
    if (this.peek().kind !== "number") this.fail("expected integer");
    return Number(this.next().text);
  }

  parse(): Query {
    this.kw("MATCH");
    let pathVar: string | null = null;
    let pathFn: Query["pathFn"] = null;
    if (this.peek().kind === "ident" && this.peek(1).text === "=") {
      pathVar = this.next().text;
      this.next();
    }
    const fnName = this.peek().text.toLowerCase();
    if (fnName === "shortestpath" || fnName === "allshortestpaths") {
      pathFn = fnName === "shortestpath" ? "shortestPath" : "allShortestPaths";
      this.next();
      this.p("(");
    } else if (pathVar) {
      this.fail("expected shortestPath or allShortestPaths");
    }
    const ns: NodePat[] = [this.nodePat()];
    const rs: RelPat[] = [];
    while (this.isP("-") || this.isP("<")) {
      rs.push(this.relPat());
      ns.push(this.nodePat());
    }
    if (pathFn) {
      this.p(")");
      if (rs.length !== 1) throw new ChqlError(`${pathFn} needs exactly one relationship`, this.peek().pos);
    }
    let where: Expr | null = null;
    if (this.isKw("WHERE")) {
      this.next();
      where = this.orExpr();
    }
    this.kw("RETURN");
    const items: Item[] = [this.item()];
    while (this.isP(",")) {
      this.next();
      items.push(this.item());
    }
    let limit: number | null = null;
    if (this.isKw("LIMIT")) {
      this.next();
      limit = this.int();
    }
    if (this.peek().kind !== "eof") this.fail("expected end of query");
    return { pathVar, pathFn, nodes: ns, rels: rs, where, items, limit };
  }

  private nodePat(): NodePat {
    this.p("(");
    const pat: NodePat = { v: null, labels: [], props: [] };
    if (this.peek().kind === "ident") pat.v = this.next().text;
    if (this.isP(":")) {
      this.next();
      pat.labels.push(this.ident("label"));
      while (this.isP("|")) {
        this.next();
        pat.labels.push(this.ident("label"));
      }
    }
    if (this.isP("{")) {
      this.next();
      do {
        if (this.isP(",")) this.next();
        const key = this.ident("property name");
        this.p(":");
        pat.props.push([key, this.literal()]);
      } while (this.isP(","));
      this.p("}");
    }
    this.p(")");
    return pat;
  }

  private relPat(): RelPat {
    let reverse = false;
    if (this.isP("<")) {
      this.next();
      reverse = true;
    }
    this.p("-");
    this.p("[");
    const rel: RelPat = { v: null, kinds: [], reverse, min: 1, max: 1 };
    if (this.peek().kind === "ident") rel.v = this.next().text;
    if (this.isP(":")) {
      this.next();
      rel.kinds.push(this.ident("edge kind"));
      while (this.isP("|")) {
        this.next();
        rel.kinds.push(this.ident("edge kind"));
      }
    }
    if (this.isP("*")) {
      this.next();
      rel.min = 1;
      rel.max = Infinity;
      if (this.peek().kind === "number") rel.min = this.int();
      if (this.isP("..")) {
        this.next();
        if (this.peek().kind === "number") rel.max = this.int();
      } else if (this.peek(-1).kind === "number") {
        rel.max = rel.min;
      }
    }
    this.p("]");
    this.p("-");
    if (this.isP(">")) {
      if (reverse) this.fail("relationship cannot point both ways");
      this.next();
    } else if (!reverse) {
      this.fail("expected '>' (undirected patterns are not supported)");
    }
    return rel;
  }

  private literal(): Literal {
    const t = this.next();
    if (t.kind === "string") return t.text;
    if (t.kind === "number") return Number(t.text);
    if (t.kind === "ident" && t.text.toLowerCase() === "days_ago") {
      this.p("(");
      const n = this.int();
      this.p(")");
      return Math.floor(Date.now() / 1000) - n * DAY;
    }
    if (t.kind === "ident") {
      const u = t.text.toUpperCase();
      if (u === "TRUE") return true;
      if (u === "FALSE") return false;
      if (u === "NULL") return null;
    }
    this.i--;
    return this.fail("expected literal");
  }

  private item(): Item {
    if (this.isP("*")) {
      this.next();
      return { t: "all" };
    }
    if (this.isKw("COUNT") && this.peek(1).text === "(") {
      this.next();
      this.next();
      const v = this.ident("variable");
      this.p(")");
      return { t: "count", v };
    }
    const v = this.ident("variable");
    if (this.isP(".")) {
      this.next();
      return { t: "prop", v, prop: this.ident("property name") };
    }
    return { t: "var", v };
  }

  private orExpr(): Expr {
    let a = this.andExpr();
    while (this.isKw("OR")) {
      this.next();
      a = { t: "bin", op: "OR", a, b: this.andExpr() };
    }
    return a;
  }
  private andExpr(): Expr {
    let a = this.notExpr();
    while (this.isKw("AND")) {
      this.next();
      a = { t: "bin", op: "AND", a, b: this.notExpr() };
    }
    return a;
  }
  private notExpr(): Expr {
    if (this.isKw("NOT")) {
      this.next();
      return { t: "not", e: this.notExpr() };
    }
    return this.cmpExpr();
  }
  private cmpExpr(): Expr {
    const a = this.primary();
    const t = this.peek();
    if (t.kind === "punct" && ["=", "<>", "<", "<=", ">", ">="].includes(t.text)) {
      this.next();
      return { t: "bin", op: t.text, a, b: this.primary() };
    }
    if (this.isKw("STARTS") || this.isKw("ENDS")) {
      const op = this.next().text.toUpperCase();
      this.kw("WITH");
      return { t: "bin", op, a, b: this.primary() };
    }
    if (this.isKw("CONTAINS") || this.isKw("IN")) {
      const op = this.next().text.toUpperCase();
      return { t: "bin", op, a, b: this.primary() };
    }
    if (this.isKw("IS")) {
      this.next();
      let negate = false;
      if (this.isKw("NOT")) {
        this.next();
        negate = true;
      }
      this.kw("NULL");
      return { t: "isnull", e: a, negate };
    }
    return a;
  }
  private primary(): Expr {
    if (this.isP("(")) {
      this.next();
      const e = this.orExpr();
      this.p(")");
      return e;
    }
    if (this.isP("[")) {
      this.next();
      const values: Literal[] = [];
      while (!this.isP("]")) {
        values.push(this.literal());
        if (!this.isP("]")) this.p(",");
      }
      this.next();
      return { t: "lit", value: values };
    }
    const t = this.peek();
    if (t.kind === "ident" && !["TRUE", "FALSE", "NULL", "DAYS_AGO"].includes(t.text.toUpperCase())) {
      const v = this.next().text;
      if (this.isP(".")) {
        this.next();
        return { t: "prop", v, prop: this.ident("property name") };
      }
      if (this.isP(":")) {
        this.next();
        return { t: "label", v, label: this.ident("label") };
      }
      return { t: "var", v };
    }
    return { t: "lit", value: this.literal() };
  }
}

// ---------------------------------------------------------------------------
// Evaluation

type Value = NodeId | Edge[];
type Binding = Map<string, Value>;

function prop(n: MockNode, key: string): unknown {
  const k = key.toLowerCase();
  if (k === "name" || k === "objectid" || k === "kind" || k === "tier0" || k === "owned" || k === "enabled") return n[k];
  return n.properties[k] ?? null;
}

function nodeMatches(n: MockNode, pat: NodePat): boolean {
  if (pat.labels.length > 0 && !pat.labels.includes(n.kind)) return false;
  return pat.props.every(([k, v]) => looseEq(prop(n, k), v));
}

function looseEq(a: unknown, b: unknown): boolean {
  if (typeof a === "string" && typeof b === "string") return a.toUpperCase() === b.toUpperCase();
  return (a ?? null) === (b ?? null);
}

function evalExpr(e: Expr, b: Binding): unknown {
  switch (e.t) {
    case "lit":
      return e.value;
    case "var":
      return b.has(e.v);
    case "prop": {
      const id = b.get(e.v);
      if (typeof id !== "number") throw new ChqlError(`'${e.v}' is not a node variable`, null, "semantic");
      return prop(nodes[id]!, e.prop);
    }
    case "label": {
      const id = b.get(e.v);
      return typeof id === "number" && nodes[id]!.kind === e.label;
    }
    case "not":
      return !evalExpr(e.e, b);
    case "isnull": {
      const isNull = evalExpr(e.e, b) == null;
      return e.negate ? !isNull : isNull;
    }
    case "bin": {
      if (e.op === "AND") return Boolean(evalExpr(e.a, b)) && Boolean(evalExpr(e.b, b));
      if (e.op === "OR") return Boolean(evalExpr(e.a, b)) || Boolean(evalExpr(e.b, b));
      const x = evalExpr(e.a, b);
      const y = evalExpr(e.b, b);
      const sx = String(x ?? "").toUpperCase();
      const sy = String(y ?? "").toUpperCase();
      switch (e.op) {
        case "=":
          return looseEq(x, y);
        case "<>":
          return !looseEq(x, y);
        case "<":
          return (x as number) < (y as number);
        case "<=":
          return (x as number) <= (y as number);
        case ">":
          return (x as number) > (y as number);
        case ">=":
          return (x as number) >= (y as number);
        case "STARTS":
          return sx.startsWith(sy);
        case "ENDS":
          return sx.endsWith(sy);
        case "CONTAINS":
          return sx.includes(sy);
        case "IN":
          return Array.isArray(y) && y.some((v) => looseEq(x, v));
      }
      return false;
    }
  }
}

/** Expands one relationship hop (possibly variable length) from `from`. */
function expand(from: NodeId, rel: RelPat): { dst: NodeId; via: Edge[] }[] {
  const f = { kinds: new Set(rel.kinds) };
  const adj = rel.reverse ? inAdj : outAdj;
  const other = (x: Edge) => (rel.reverse ? x.src : x.dst);
  const out: { dst: NodeId; via: Edge[] }[] = [];
  const seen = new Set<NodeId>([from]);
  let frontier: { id: NodeId; via: Edge[] }[] = [{ id: from, via: [] }];
  for (let depth = 1; depth <= rel.max && frontier.length > 0; depth++) {
    const next: { id: NodeId; via: Edge[] }[] = [];
    for (const { id, via } of frontier) {
      for (const edge of adj[id] ?? []) {
        if (!edgeAllowed(edge, f)) continue;
        const dst = other(edge);
        if (rel.max > 1 && seen.has(dst)) continue;
        seen.add(dst);
        const step = { id: dst, via: [...via, edge] };
        next.push(step);
        if (depth >= rel.min) out.push({ dst, via: step.via });
      }
    }
    frontier = next;
  }
  return out;
}

const MAX_BINDINGS = 20000;

function bindChain(q: Query): Binding[] {
  const first = q.nodes[0]!;
  let bindings: { b: Binding; at: NodeId }[] = nodes
    .filter((n) => nodeMatches(n, first))
    .map((n) => ({ b: new Map<string, Value>(first.v ? [[first.v, n.id]] : []), at: n.id }));
  q.rels.forEach((rel, i) => {
    const pat = q.nodes[i + 1]!;
    const next: typeof bindings = [];
    for (const { b, at } of bindings) {
      for (const { dst, via } of expand(at, rel)) {
        if (!nodeMatches(nodes[dst]!, pat)) continue;
        const bound = pat.v ? b.get(pat.v) : undefined;
        if (bound !== undefined && bound !== dst) continue;
        const nb = new Map(b);
        if (pat.v) nb.set(pat.v, dst);
        nb.set(rel.v ?? `#r${i}`, via);
        next.push({ b: nb, at: dst });
        if (next.length > MAX_BINDINGS) throw new ChqlError("pattern too broad for the mock engine", null, "semantic");
      }
    }
    bindings = next;
  });
  return bindings.map((x) => x.b);
}

function bindPaths(q: Query): Binding[] {
  const [a, b] = [q.nodes[0]!, q.nodes[1]!];
  const rel = q.rels[0]!;
  const f = { kinds: new Set(rel.kinds) };
  const isTarget = (id: NodeId) => nodeMatches(nodes[id]!, b);
  const out: Binding[] = [];
  for (const start of nodes.filter((n) => nodeMatches(n, a))) {
    if (q.pathFn === "shortestPath") {
      const path = shortestPath(start.id, isTarget, f, rel.max);
      if (!path || path.length < rel.min) continue;
      const bind = new Map<string, Value>([[q.pathVar ?? "#p", path]]);
      if (a.v) bind.set(a.v, start.id);
      if (b.v) bind.set(b.v, path[path.length - 1]!.dst);
      out.push(bind);
    } else {
      const es = allShortestPathEdges(start.id, isTarget, f);
      if (es.length === 0) continue;
      const bind = new Map<string, Value>([[q.pathVar ?? "#p", es]]);
      if (a.v) bind.set(a.v, start.id);
      out.push(bind);
    }
  }
  return out;
}

/** Enumerates hop sequences through an edge DAG (union of shortest paths) from `start`. */
function edgesToHops(start: NodeId, es: Edge[], cap = 50): Edge[][] {
  const bySrc = new Map<NodeId, Edge[]>();
  for (const x of es) bySrc.set(x.src, [...(bySrc.get(x.src) ?? []), x]);
  const out: Edge[][] = [];
  const walk = (at: NodeId, hops: Edge[], seen: Set<NodeId>) => {
    if (out.length >= cap) return;
    const nexts = bySrc.get(at) ?? [];
    if (nexts.length === 0) {
      if (hops.length > 0) out.push(hops);
      return;
    }
    for (const x of nexts) if (!seen.has(x.dst)) walk(x.dst, [...hops, x], new Set([...seen, x.dst]));
  };
  walk(start, [], new Set([start]));
  return out;
}

/** Parses without executing (used to validate saved queries). */
export function parseChql(src: string): void {
  new Parser(lex(src)).parse();
}

export function runChql(src: string, requestLimit: number): GraphResult {
  const started = performance.now();
  const q = new Parser(lex(src)).parse();
  const declared = new Set<string>([...q.nodes.map((n) => n.v), ...q.rels.map((r) => r.v), q.pathVar].filter((v): v is string => !!v));
  for (const item of q.items) {
    if (item.t !== "all" && !declared.has(item.v)) {
      throw new ChqlError(
        `unknown variable '${item.v}'`,
        src.indexOf(item.v, src.toUpperCase().lastIndexOf("RETURN")),
        "semantic",
      );
    }
  }

  let bindings = q.pathFn ? bindPaths(q) : bindChain(q);
  if (q.where) {
    const where = q.where;
    bindings = bindings.filter((b) => Boolean(evalExpr(where, b)));
  }
  const limit = Math.min(q.limit ?? requestLimit, requestLimit);
  const truncated = bindings.length > limit && !q.items.some((i) => i.t === "count");

  const scalarItems = q.items.filter((i) => i.t === "prop" || i.t === "count");
  const elapsed = () => Math.round((performance.now() - started) * 100) / 100;

  if (scalarItems.length > 0) {
    const columns = scalarItems.map((i) => (i.t === "count" ? `count(${i.v})` : `${i.v}.${i.prop}`));
    const hasCount = scalarItems.some((i) => i.t === "count");
    const rowKey = (b: Binding) =>
      scalarItems.filter((i) => i.t === "prop").map((i) => (i.t === "prop" ? prop(nodes[b.get(i.v) as NodeId]!, i.prop) : null));
    let rows: unknown[][];
    if (hasCount) {
      const groups = new Map<string, { key: unknown[]; seen: Map<string, Set<string>> }>();
      for (const b of bindings) {
        const key = rowKey(b);
        const k = JSON.stringify(key);
        const g = groups.get(k) ?? { key, seen: new Map() };
        for (const i of scalarItems) {
          if (i.t !== "count") continue;
          const set = g.seen.get(i.v) ?? new Set<string>();
          set.add(JSON.stringify(b.get(i.v)));
          g.seen.set(i.v, set);
        }
        groups.set(k, g);
      }
      if (groups.size === 0) groups.set("[]", { key: [], seen: new Map() });
      rows = [...groups.values()].map((g) => {
        let ki = 0;
        return scalarItems.map((i) => (i.t === "count" ? (g.seen.get(i.v)?.size ?? 0) : g.key[ki++]));
      });
    } else {
      rows = bindings.slice(0, limit).map(rowKey);
    }
    return { nodes: [], edges: [], columns, rows: rows.slice(0, limit), truncated, elapsed_ms: elapsed() };
  }

  const wantAll = q.items.some((i) => i.t === "all");
  const wanted = new Set(q.items.flatMap((i) => (i.t === "var" ? [i.v] : [])));
  const nodeIds = new Set<NodeId>();
  const edgeSet = new Set<Edge>();
  const pathHops: Edge[][] = [];
  const nodeVarsReturned = q.nodes.filter((n) => n.v && (wantAll || wanted.has(n.v))).length;
  for (const b of bindings.slice(0, limit)) {
    for (const [v, val] of b) {
      const isWanted = wantAll || wanted.has(v);
      if (typeof val === "number") {
        if (isWanted) nodeIds.add(val);
      } else if (isWanted || (v.startsWith("#") && nodeVarsReturned > 1)) {
        // Edges connecting several returned nodes are included so the result is a readable subgraph.
        val.forEach((x) => edgeSet.add(x));
        const start = val.find((x) => !val.some((y) => y.dst === x.src))?.src;
        if ((v === q.pathVar || v === "#p") && start !== undefined) pathHops.push(...edgesToHops(start, val));
      }
    }
  }
  return resultFrom(nodeIds, [...edgeSet], {
    ...(q.pathFn
      ? { paths: pathHops.map((h) => [h[0]!.src, ...h.map((x) => x.dst)]), path_hops: pathHops.map((h) => h.map((x) => ({ ...x }))) }
      : {}),
    truncated,
    elapsed_ms: elapsed(),
  });
}
