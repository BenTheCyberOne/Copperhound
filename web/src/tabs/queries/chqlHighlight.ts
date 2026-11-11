// Lightweight CHQL tokenizer for syntax highlighting (not a parser: it only needs
// to classify characters; the server reports real syntax errors with a position).

export type TokenClass = "kw" | "fn" | "label" | "str" | "num" | "comment" | "prop" | "op" | "plain";

export interface Token {
  text: string;
  cls: TokenClass;
  /** UTF-16 offset of the token in the source. */
  start: number;
}

/** Clause and expression keywords (docs/CHQL.md grammar), matched case-insensitively. */
export const KEYWORDS = new Set([
  "MATCH",
  "OPTIONAL",
  "WHERE",
  "RETURN",
  "WITH",
  "UNWIND",
  "UNION",
  "ALL",
  "AS",
  "ORDER",
  "BY",
  "SKIP",
  "LIMIT",
  "DISTINCT",
  "ASC",
  "ASCENDING",
  "DESC",
  "DESCENDING",
  "CASE",
  "WHEN",
  "THEN",
  "ELSE",
  "END",
  "AND",
  "OR",
  "XOR",
  "NOT",
  "IN",
  "IS",
  "NULL",
  "TRUE",
  "FALSE",
  "STARTS",
  "ENDS",
  "CONTAINS",
]);

const IDENT = /[A-Za-z_][A-Za-z0-9_]*/y;
const NUMBER = /\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

export function tokenize(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  const push = (cls: TokenClass, end: number) => {
    const last = out[out.length - 1];
    // Merge runs of plain text to keep the DOM small.
    if (cls === "plain" && last?.cls === "plain") last.text += src.slice(i, end);
    else out.push({ text: src.slice(i, end), cls, start: i });
    i = end;
  };
  while (i < src.length) {
    const c = src[i]!;
    const next = src[i + 1];
    if (c === "/" && next === "/") {
      const nl = src.indexOf("\n", i);
      push("comment", nl === -1 ? src.length : nl);
    } else if (c === "/" && next === "*") {
      const close = src.indexOf("*/", i + 2);
      push("comment", close === -1 ? src.length : close + 2);
    } else if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src[j] === "\\" ? 2 : 1;
      push("str", Math.min(j + 1, src.length));
    } else if (c === "`") {
      const close = src.indexOf("`", i + 1);
      push("plain", close === -1 ? src.length : close + 1);
    } else if (/\d/.test(c)) {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(src);
      push("num", i + (m?.[0].length ?? 1));
    } else if (/[A-Za-z_]/.test(c)) {
      IDENT.lastIndex = i;
      const word = IDENT.exec(src)![0];
      const end = i + word.length;
      const prev = src.slice(0, i).trimEnd();
      const before = prev[prev.length - 1];
      const after = src.slice(end).trimStart()[0];
      let cls: TokenClass = "plain";
      if (before === ":" || (before === "|" && /:\s*[A-Za-z_][\w]*\s*\|?\s*$/.test(prev.slice(-80)))) cls = "label";
      else if (before === ".") cls = "prop";
      else if (after === "(") cls = "fn";
      else if (KEYWORDS.has(word.toUpperCase())) cls = "kw";
      push(cls, end);
    } else if ("=<>!~+-*/%^|".includes(c)) {
      let j = i + 1;
      while (j < src.length && "=<>~-".includes(src[j]!) && j - i < 3) j++;
      push("op", j);
    } else {
      push("plain", i + 1);
    }
  }
  return out;
}

/** Keywords for the quick reference, grouped. */
export const SYNTAX_SUMMARY: { title: string; lines: string[] }[] = [
  {
    title: "Clauses",
    lines: [
      "[OPTIONAL] MATCH <pattern>[, …] [WHERE <expr>]",
      "UNWIND <list> AS x",
      "WITH [DISTINCT] <items> [ORDER BY …] [SKIP n] [LIMIT n] [WHERE …]",
      "RETURN [DISTINCT] <items> [ORDER BY <expr> [ASC|DESC], …] [SKIP n] [LIMIT n]",
      "<query> UNION [ALL] <query>",
    ],
  },
  {
    title: "Patterns",
    lines: [
      "(n:User {name:'ALICE@CORP.LOCAL'})   (n:User|Computer)",
      "(a)-[:MemberOf*1..]->(g)   (a)<-[r:AdminTo|CanRDP]-(b)",
      "p = shortestPath((a)-[*1..]->(b))   allShortestPaths(…)",
    ],
  },
  {
    title: "Expressions",
    lines: [
      "= <> < <= > >=   STARTS WITH | ENDS WITH | CONTAINS | =~ '(?i)re'",
      "IN [..]   IS [NOT] NULL   AND OR XOR NOT   CASE WHEN … THEN … ELSE … END",
      "count(*) count(DISTINCT x) collect min max sum avg   days_ago(90)",
      "any/all/none/single(x IN list WHERE …)   [x IN list WHERE … | …]",
    ],
  },
];
