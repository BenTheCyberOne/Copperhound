# CHQL — CopperHound Query Language

CHQL is a read-only Cypher dialect compiled to native operations on the
memory-mapped CSR graph: hash/prefix index lookups, parallel filtered scans,
per-hop expansion, BFS for variable-length hops and bidirectional / multi-source
BFS for path functions. Most BloodHound (CE and legacy) Cypher queries run
unchanged — see [Cypher compatibility](#cypher-compatibility).

Run it with `POST /api/v1/query` (see [API.md](API.md)), from the UI query
editor, or on the command line: `copperhound query corp.chg "MATCH …"`.

## Quick tour

```cypher
// Kerberoastable users
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' RETURN u

// Shortest path from a user to Tier Zero
MATCH p = shortestPath((u:User {name:'JDOE@CORP.LOCAL'})-[*1..]->(t {tier0:true})) RETURN p

// Owned principals to Domain Admins (joins, path per pair)
MATCH (n {owned:true}), (m:Group) WHERE m.objectid ENDS WITH '-512'
MATCH p = shortestPath((n)-[*1..]->(m)) RETURN p

// Aggregation, ordering, paging
MATCH (n)-[:AdminTo]->(c:Computer)
WITH c, count(n) AS admins WHERE admins > 5
RETURN c.name, admins ORDER BY admins DESC, c.name SKIP 10 LIMIT 10

// Exclusion via collect + IN, OPTIONAL MATCH, pattern predicates
MATCH (dc)-[:MemberOf*0..]->(g:Group) WHERE g.objectid ENDS WITH '-516'
WITH collect(dc) AS dcs
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c IN dcs
OPTIONAL MATCH (c)-[:HasSession]->(u:User)
RETURN c.name, collect(u.name) AS sessions

MATCH (u:User)-[:AdminTo]->(c:Computer) WHERE NOT (c)-[:HasSession]->(u) RETURN u, c
```

## Grammar

Keywords are case-insensitive. `//` and `/* … */` are comments; a trailing `;`
is allowed.

```ebnf
query        = single_query { "UNION" [ "ALL" ] single_query } ;
single_query = { clause } return ;
clause       = [ "OPTIONAL" ] "MATCH" pattern { "," pattern } [ "WHERE" expr ]
             | "UNWIND" expr "AS" ident
             | "WITH" projection [ "WHERE" expr ] ;
return       = "RETURN" projection ;
projection   = [ "DISTINCT" ] ( "*" [ "," items ] | items )
               [ "ORDER" "BY" expr [ "ASC" | "DESC" ] { "," expr [ "ASC" | "DESC" ] } ]
               [ "SKIP" int ] [ "LIMIT" int ] ;
items        = expr [ "AS" ident ] { "," expr [ "AS" ident ] } ;

pattern      = [ ident "=" ] ( ( "shortestPath" | "allShortestPaths" ) "(" chain ")" | chain ) ;
chain        = node { rel node } ;
node         = "(" [ ident ] { ":" label { "|" [ ":" ] label } } [ "{" key ":" expr { "," key ":" expr } "}" ] ")" ;
rel          = ( "-" | "<-" ) [ "[" [ ident ] [ ":" type { "|" [ ":" ] type } ] [ "*" [ int ] [ ".." [ int ] ] ] "]" ] ( "->" | "-" ) ;

expr         = or ;  or = xor { "OR" xor } ;  xor = and { "XOR" and } ;  and = not { "AND" not } ;
not          = "NOT" not | comparison ;
comparison   = additive { ( "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "=~" | "IN"
                          | "STARTS" "WITH" | "ENDS" "WITH" | "CONTAINS" ) additive
                          | "IS" [ "NOT" ] "NULL" } ;
additive     = multiplicative { ( "+" | "-" ) multiplicative } ;
multiplicative = power { ( "*" | "/" | "%" ) power } ;   power = unary { "^" unary } ;
unary        = [ "-" | "+" ] postfix ;
postfix      = atom { "." key | "[" expr "]" | "[" [ expr ] ".." [ expr ] "]" | ":" label } ;
atom         = literal | ident | "(" expr ")" | chain        (* pattern predicate, ≥ 1 relationship *)
             | "[" [ expr { "," expr } ] "]"
             | "[" ident "IN" expr [ "WHERE" expr ] [ "|" expr ] "]"   (* list comprehension *)
             | ( "any" | "all" | "none" | "single" ) "(" ident "IN" expr "WHERE" expr ")"
             | "CASE" [ expr ] { "WHEN" expr "THEN" expr } [ "ELSE" expr ] "END"
             | name "(" [ "DISTINCT" ] ( "*" | [ expr { "," expr } ] ) ")" ;
literal      = string | int | float | "true" | "false" | "null" ;
```

Strings use `'…'` or `"…"` with `\n \t \r \\ \' \"` escapes; regex escapes such as
`\.` or `\d` are kept as written. Identifiers may be quoted with backticks.

## Patterns

| Pattern | Meaning |
|---|---|
| `(n)` | any node |
| `(n:User)` / `(n:User\|Computer)` / `(n:Group:Base)` | kind; `\|` = either, chained `:` = all |
| `(n:Base)` / `(n:AZBase)` | any Active Directory / any Azure node |
| `(n:Tag_Tier_Zero)` / `(n:Tag_Owned)` | Tier Zero / owned flag (BloodHound CE tag labels) |
| `(n {name:'X', enabled:true})` | inline property equality (any expression of earlier variables allowed) |
| `(a)-[:MemberOf]->(b)`, `(a)<-[:AdminTo]-(b)` | one hop, either direction |
| `(a)-[r:AdminTo\|CanRDP]-(b)` | undirected: follows edges both ways |
| `(a)-[:MemberOf*1..]->(g)`, `*`, `*2`, `*..3`, `*0..` | variable length (default `*1..`), any direction |
| `(a)-->(b)-->(c)`, `(a)-->(b), (b)-->(c)` | chains; comma patterns join on shared variables |
| `p = (a)-[:X]->(b)` | path variable over any pattern |
| `p = shortestPath((a)-[*1..]->(b))` | one shortest path per start node |
| `p = allShortestPaths((a)-[*1..]->(b))` | union of all shortest paths (one subgraph) |

Relationship type rules:

* A fixed hop without types follows **every** edge kind; variable-length hops and
  path functions without types follow **traversable** kinds only (the attack-path
  set; `GetChanges`, `TrustedBy`… are not traversable). Name a kind to follow it.
* A type list may contain kinds that do not exist in the data set (they match
  nothing, as in Neo4j); a list made **only** of unknown kinds is an error, which
  catches typos.

## Semantics

* **Joins.** Patterns in one `MATCH` and successive `MATCH` clauses join on shared
  variables (nested loops; each pattern starts from an already-bound node when it
  has one). Variables are per-row, as in Cypher.
* **OPTIONAL MATCH** keeps the input row with `null`s when the clause (including
  its `WHERE`) matches nothing.
* **Relationship uniqueness.** Within one `MATCH` clause a fixed-length
  relationship is never bound twice (Cypher isomorphism), so
  `(a)-[:MemberOf]->(g)<-[:MemberOf]-(b)` never yields `a = b`.
* **Variable-length hops** use *reachability* semantics: each reachable end node is
  produced once (with one shortest witness path), not once per distinct path,
  which keeps `*1..` bounded on large graphs. A bound end node stops the BFS
  when reached.
* **shortestPath** with both endpoints bound per row (from earlier patterns or
  clauses) returns the shortest path for that pair. With a set of end nodes it
  returns, for each start node, a shortest path to the *nearest* end node (one row
  per start node). Undirected and bounded (`*1..4`) forms are supported.
* **allShortestPaths** returns one row whose path value is the union of every
  shortest path from each start node to its nearest end node (rendered as a
  subgraph; `nodes(p)` / `relationships(p)` work on it).
* **WITH** projects, aggregates, deduplicates (`WITH DISTINCT`), orders and pages;
  only the projected names stay in scope. `WHERE` after `WITH` filters projected
  rows (use it for `HAVING`-style filters on aggregates).
* **Aggregation** groups by every non-aggregate item. Global aggregation over no
  rows returns one row (`count` = 0). When a final `RETURN` aggregates without
  `ORDER BY`, rows are sorted by the first aggregate descending (Cypher leaves the
  order undefined; this keeps "top N" queries useful).
* **ORDER BY** accepts output aliases, any returned expression written the same
  way (`ORDER BY count(c) DESC`), and input variables (`ORDER BY u.name` after
  `RETURN u`). Nulls sort last ascending and first descending.
* **UNION** requires identical column names; `UNION` removes duplicate rows,
  `UNION ALL` keeps them.
* **Comparisons**: string comparisons (`=`, `<>`, `STARTS WITH`, `ENDS WITH`,
  `CONTAINS`, `IN`, `=~`) are **case-insensitive**. `list = value` is true when
  the list contains the value (collector properties are often lists).
* **Null handling**: `WHERE` uses two-valued logic — a `null` condition is false
  and `NOT null` is true (Cypher's three-valued logic would drop the row). Use
  `IS NULL` / `IS NOT NULL` / `coalesce()` to be explicit.
* **Arithmetic** is floating point: `count(x) / 2` is `2.5`, not `2`; use
  `toInteger()` / `floor()` to truncate. Integral results render as integers.
* `=~` matches the whole string (Cypher semantics), case-insensitively; patterns
  are limited to 1024 characters and compile with bounded automaton sizes.

## Properties

Fast columnar properties: `name`, `objectid`, `kind` (also `label`), `id`, and the
flags `tier0` (alias `highvalue_tier0`, `isTierZero`), `owned`, `enabled`,
`admincount`, `highvalue`, `unconstraineddelegation`, `dontreqpreauth`, `hasspn`.
`system_tags` includes `admin_tier_0` for Tier Zero and `owned` for owned objects
(plus any collector value), so BloodHound CE's
`COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0'` works. Every other property
is read from the collector's raw properties (missing → `null`).

Relationships carry no properties: `type(r)` / `r.type` / `r.kind` give the kind,
other `r.*` are `null`. A variable-length `r` is a list of relationships.

## Functions

| Group | Functions |
|---|---|
| Aggregates | `count(*)`, `count([DISTINCT] x)`, `collect([DISTINCT] x)` (≤ 100 000 items), `min`, `max`, `sum`, `avg`, `stdev`, `stdevp` |
| Strings | `toLower`/`lower`, `toUpper`/`upper`, `trim`, `ltrim`, `rtrim`, `split`, `substring`, `replace`, `left`, `right`, `reverse`, `toString` |
| Conversion | `toInteger`/`toInt`, `toFloat`, `toBoolean` (and `…OrNull` aliases), `coalesce` |
| Lists | `size`, `head`, `last`, `tail`, `reverse`, `range`, `isEmpty`, `[x IN l WHERE … \| …]`, `l[i]`, `l[a..b]`, `any/all/none/single(x IN l WHERE …)` |
| Graph | `id`, `elementId`, `labels`, `type`, `nodes`, `relationships`/`rels`, `startNode`, `endNode`, `length`, `keys`, `properties`, `exists(n.prop)`, `exists((a)-->(b))`, `size((a)-->(b))` (match count) |
| Numbers | `abs`, `round`, `floor`, `ceil`, `sqrt`, `sign` |
| Time | `datetime().epochseconds` / `.epochmillis`, `timestamp()`, `now()`, `days_ago(n)` (epoch seconds `n` days ago) |

`CASE WHEN … THEN … ELSE … END` and `CASE x WHEN v THEN … END` are supported.

## Results

Node, relationship and path values (also inside lists, e.g. `collect(n)` or
`nodes(p)`) fill `nodes` / `edges` / `paths` for the graph canvas. When any
returned item is not a plain variable, or a variable holds a scalar, the result
also has `columns` / `rows` (nodes render as names, relationships as kind names).
`truncated` is set when `LIMIT` (or the request's default limit) cut rows, or a
safety bound was hit.

## Limits and cancellation

| Bound | Value |
|---|---|
| Rows returned | request `limit` (default 1000), hard cap 100 000 |
| Rows produced by `MATCH` stages per query | 50 000 000 (then `truncated`) |
| Groups per aggregation | 2 000 000 (error) |
| Rows buffered by `ORDER BY` without `LIMIT` / by `DISTINCT` | 5 000 000 (error) |
| `allShortestPaths` subgraph edges | the result limit (then `truncated`) |
| Query text | 256 KiB; nesting depth 200 |

Execution streams in waves: a `LIMIT` stops the producers early, aggregation
keeps only per-group state (built per thread and merged), and `ORDER BY … LIMIT`
keeps a bounded top-k buffer. Every operator polls the cancellation token, so the
API timeout (`timeout_ms`) and `DELETE /query/{id}` stop any query promptly.

Errors carry `code` (`syntax`, `semantic`, `timeout`, `cancelled`) and, for
syntax errors and most semantic errors (unknown variable / function /
relationship type / label), a byte `position` into the query text.

## Cypher compatibility

| Feature | Status |
|---|---|
| `MATCH`, multiple comma patterns, multiple `MATCH` clauses | ✅ joins on shared variables |
| `OPTIONAL MATCH` | ✅ |
| `WHERE` (`AND OR XOR NOT`, comparisons, `IN`, `STARTS WITH`, `ENDS WITH`, `CONTAINS`, `=~`, `IS [NOT] NULL`) | ✅ string ops case-insensitive |
| Label predicates `n:User`, multi-label `:A:B`, `:A\|B` | ✅ `Base`/`AZBase`/`Tag_*` mapped |
| Pattern predicates `(a)-->(b)`, `NOT (a)-[:X]->(b)`, `exists((…))` | ✅ |
| `WITH` (projection, aggregation, `DISTINCT`, `WHERE`, `ORDER BY`/`SKIP`/`LIMIT`) | ✅ |
| `RETURN [DISTINCT]`, `ORDER BY … ASC/DESC`, `SKIP`, `LIMIT`, `RETURN *` | ✅ |
| `count(*)`, `count(DISTINCT x)`, `collect`, `min`, `max`, `sum`, `avg`, `stdev` | ✅ |
| `UNWIND` | ✅ |
| `UNION` / `UNION ALL` | ✅ |
| Undirected `-[r:A\|B]-`, variable length `*min..max` in all directions | ✅ reachability semantics |
| `shortestPath` / `allShortestPaths` | ✅ one path per start / union subgraph (see Semantics) |
| List comprehension, `any/all/none/single`, `CASE`, list index/slice | ✅ |
| Legacy `size((pattern))` | ✅ counts matches |
| String, list, numeric, conversion, graph functions | ✅ common set (table above) |
| `datetime().epochseconds` | ✅ other temporal types (`date()`, `duration()`) ❌ |
| Pattern comprehension `[(a)-->(b) \| b.name]` | ❌ use `OPTIONAL MATCH` + `collect` |
| `EXISTS { … }` / `COUNT { … }` subqueries (Neo4j 5) | ❌ use `exists((…))` / `size((…))` |
| Parameters `$name` | ❌ inline values |
| `CALL` procedures, APOC, GDS | ❌ |
| `CREATE`, `MERGE`, `SET`, `DELETE`, `REMOVE` | ❌ read-only (mark owned objects via the API) |
| Relationship properties (`r.isacl`, `r.trusttype`…) | ⚠️ parse, evaluate to `null` |
| Three-valued logic for `NOT null` | ⚠️ two-valued (null is false) |
| Integer division | ⚠️ floating-point division |
| Map literals `{a: 1}` outside node patterns | ❌ |

### Port check

`crates/query/tests/cypher_compat.rs` runs 64 popular BloodHound queries — the
BloodHound CE pre-built library (Kerberoastable / AS-REP roastable users, all
Domain Admins, shortest paths to Domain Admins / Tier Zero / unconstrained
delegation, owned-to-Tier-Zero paths, DCSync principals, foreign group
membership, Domain Users rights, DA logons to non-DCs, unconstrained/constrained/
RBCD delegation, stale accounts and passwords, unsupported OS, ESC1 templates,
domain controllers, GPO links, Entra Global Administrators, …), the legacy
BloodHound pre-built queries, and common community queries (top admins, session
counts, percentage of users with a path to DA, `size()` counts, `UNION` lists).
All run **unchanged** on a hand-built AD fixture and on a synthetic domain;
every one expected to find something does.

Queries that need a change (rewrites are also in the test):

| Original construct | Why | Rewrite |
|---|---|---|
| `[(u)-[:AdminTo]->(c) \| c.name]` | pattern comprehensions unsupported | `OPTIONAL MATCH (u)-[:AdminTo]->(c) … collect(c.name)` |
| `{name: $name}` | parameters unsupported | inline the literal |
| `CALL apoc.…` | no procedures | plain `MATCH … RETURN` |
| `WHERE EXISTS { MATCH … }` | Neo4j 5 subqueries | `WHERE exists((u)-[:AdminTo]->(:Computer))` |
| `SET u.owned = true` | read-only | mark owned objects through the API / UI |
| `-[:SQLAdmin]->` (only unknown kinds) | type list made only of kinds CHQL does not model | add a known kind or drop the hop |

## Performance notes

* `name` / `objectid` equality and `IN [...]` lists use the hash index;
  `name STARTS WITH` uses the sorted name index; other node predicates are
  pushed down to the property columns (below) or, where that is not exact,
  evaluated per candidate (flags from the flag column, other properties from
  the raw JSON).
* The planner starts each pattern from a bound node, else an indexed
  `name`/`objectid` node, else a `name STARTS WITH` end, else the end with
  fewer candidates; the first pattern fans out over all cores.
* Prefer `shortestPath` over unbounded `*1..` chains when you only need
  reachability to a target set.

### Predicate pushdown

Labels, inline `{prop: value}` maps and every single-variable `WHERE`
conjunct whose meaning the property-column store reproduces exactly are
compiled into one `ch_store::Filter` per pattern node and answered by
`Graph::filter` from kind/flag bitmaps, string dictionaries, equality bitmaps,
numeric columns and the folded name index (ARCHITECTURE.md, "Property
columns").

* **Pushed:** `=`, `<>`, `<`, `<=`, `>`, `>=`, `STARTS WITH`, `ENDS WITH`,
  `CONTAINS`, `IN` between a property and a constant (constant expressions
  such as `days_ago(90)` included), `IS [NOT] NULL`, bare `n.prop`
  truthiness, labels (`Base`/`AZBase` and `Tag_*` included), and `AND` /
  `OR` / `NOT` of those.
* **Not pushed** (evaluated per node, only on nodes the bitmap admits):
  functions of properties (`toLower(n.x)`, `coalesce(...)`), `=~`, `XOR`,
  comparisons between variables, pattern predicates.
* **Where it applies.** A pattern's start candidates come from the bitmap
  instead of a per-node scan; when a pattern starts from ≥ 4096 candidates,
  the other positions' property predicates are answered by bitmap
  membership while walking. Patterns started from variables bound earlier
  (later clauses, pattern predicates) still evaluate per node.
* **Same plan, same order.** The start node is chosen as above (candidate
  counts now come from bitmaps) and candidates keep ascending id order, so
  rows come out exactly as without pushdown. Starting from a more selective
  *middle* node was left out on purpose: it would reorder rows, which is
  visible through `collect()`, `LIMIT` without `ORDER BY` and variable-length
  witness paths.
* **Columns required.** Until the property columns are built (the server
  builds them in the background after loading a graph; `copperhound query`
  loads them), queries use the per-node evaluator.
* **Switches.** `COPPERHOUND_CHQL_PUSHDOWN=0` turns pushdown off;
  `COPPERHOUND_VERIFY_PUSHDOWN=1` evaluates every pushed predicate both ways
  and panics on the first difference; `copperhound query --no-pushdown` and
  `--compare --repeat N` measure both paths and check the results agree.

**Exactness.** A predicate is pushed only where the store's semantics are
CHQL's, edge cases included (nulls, mixed types, list values, numeric
strings, case variants, duplicate keys):

* Kept in the evaluator: `system_tags` (synthesised from flags by CHQL);
  `enabled` leaves whose outcome differs between null and `false` (`IS
  NULL`, `= false`, `<> true`, …) because the store reads a JSON `null`
  `enabled` (flag unset) as `false`; `=` / `<>` / `IN` / string operators
  with the constant on the left (`'x' = n.list` is not membership); constants
  without a JSON form (NaN, maps).
* Fixed in the store to match CHQL: `n.x <> null` matches nothing; `null IN
  [null]` is false; string `<`/`>` break case-folded ties by the exact bytes
  (`'a' > 'A'`); `objectid = '…'` returns every node sharing the object id
  and handles the empty id.
* Tests compare full result sets with pushdown on (verified node by node) and
  off for the Cypher-compat suite, every library query and thousands of
  random predicates on random property graphs
  (`crates/query/tests/pushdown.rs`; `COPPERHOUND_PUSHDOWN_ROUNDS=N` for more).

10.8M nodes / 58M edges (`synth --users 8000000 --computers 1600000 --groups
400000 --domains 4 --rich-props`), warm cache, median of 5:

| query | result | pushdown | per node |
|---|---|---|---|
| enabled kerberoastable users in a domain, `RETURN count(u)` | 52,745 | **2.2 ms** | 310 ms |
| same, `RETURN u` (first 1,000) | 1,000 | **2.1 ms** | 298 ms |
| computers with OS `= 'Windows Server 2016 Standard'` (first 1,000) | 1,000 | **2.1 ms** | 58 ms |
| computers with OS `CONTAINS 'Windows 7'`, count | 227,904 | **3.1 ms** | 77 ms |
| enabled users, `lastlogon < 1650000000`, count | 1,005,038 | **19 ms** | 341 ms |
| `n.name CONTAINS '123456'` (all kinds) | 40 | **4.5 ms** | 99 ms |
| users, `description CONTAINS 'application 42'`, count | 17,669 | **0.8 ms** | 320 ms |
| `(u:User)-[:MemberOf]->(g:Group)` with `u.hasspn` and `g.domain`, count | 840,931 | **18 ms** | 77 ms |
| library `kerberoastable-old-pw` (first 1,000) | 1,000 | **16 ms** | 32 ms |
| library `passwords-in-descriptions` | 0 | **0.4 ms** | 648 ms |
| library `legacy-os` without the `VISTA` term (first 1,000) | 1,000 | **4.9 ms** | 228 ms |
| library `no-laps` (first 1,000) | 1,000 | **6.0 ms** | 63 ms |
| library `domain-controllers` | 4 | 15 ms | 18 ms |
| library `users-to-da` (`shortestPath`, 200 paths) | 200 | 1.65 s | 1.66 s |

Queries without pushable property predicates (`MATCH (c:Computer) RETURN
c.operatingsystem, count(c)`, `MATCH (n) RETURN n.kind, count(n)`, `(u:User)
-[:MemberOf]->(g:Group)` counts, `toLower(...)` filters, name-index lookups)
run within measurement noise of the per-node path.
