# Performance

## Design

Graph-database-backed tools spend most of their time on per-row transactional
inserts during ingest and on general-purpose query planning afterwards, which on
multi-gigabyte collections means long imports and slow queries. CopperHound
instead:

- **memory-maps** collector files and splits them into records with a SIMD
  structural scanner — in parallel even within a single huge file;
- **deserialises records on every core** and interns object IDs to dense
  `u32` ids;
- builds a **compressed sparse row (CSR)** graph (outbound + inbound) with
  parallel counting sort and per-node dedup;
- writes it as raw columns that **open in milliseconds** via `mmap`;
- runs purpose-built algorithms on the CSR: bidirectional BFS for paths, a
  single reverse BFS + path-counting pass for Tier Zero exposure.

## Choke points

`tier0` performs one reverse BFS from all Tier Zero objects, counts shortest
paths (σ) on the resulting DAG, then pushes one unit of flow from every exposed
user and computer toward Tier Zero, split proportionally over equal-length
paths. Each edge's flow is the number of principals whose shortest attack
paths cross it, so remediate the top edges first. It runs in linear time,
O(V + E).

## Benchmarks

Synthetic SharpHound v6 data (`copperhound synth`), 18-thread desktop, Windows 11,
files in OS cache.

| dataset | input | objects | edges | ingest (total) |
|---|---|---|---|---|
| 2M users / 400k computers / 100k groups | 2.0 GB | 2.5M | 13.1M | **6.2 s** |
| 10M users / 2M computers / 500k groups | 10.0 GB | 12.5M | 65.7M | **23–31 s** |

Raw LDAP dumps (`copperhound synth --ldif`: every object has objectSid,
objectGUID and a 14–16 ACE `nTSecurityDescriptor`; both passes over the
memory-mapped file, properties kept):

| dataset | input | objects | edges | parse (both passes) | ingest (total) |
|---|---|---|---|---|---|
| LDIF, 800k users / 150k computers / 50k groups | 1.3 GB | 1M | 8.0M | 2.1–2.8 s (≈ 400k objects/s) | 4.4–5.6 s |
| same, as AD Explorer snapshot | 1.3 GB | 1M | 8.0M | 2.1 s (+ 0.2–1.6 s object walk) | 4.8–6.3 s |
| LDIF, 8M users / 1.5M computers / 500k groups | 12.9 GB | 10M | 79.7M | **19.5 s (513k objects/s, 680 MB/s)** | 56 s (30 s with `--no-props`) |

Queries on the 10 GB graph (12.5M nodes, 65.7M edges):

| query | time |
|---|---|
| open graph | 2 ms |
| shortest path, user → nearest Tier Zero (6 hops) | 0.75 ms |
| shortest path, user → Domain Admins | 1.6 ms |
| blast radius of a user (reaches 12.5M objects) | 1.2 s |
| full Tier Zero exposure + choke-point ranking | 8 s |

Reproduce:

```sh
cargo build --release
target/release/copperhound synth -o bench/huge --users 10000000 --computers 2000000 --groups 500000
target/release/copperhound ingest bench/huge -o bench/huge.chg
target/release/copperhound tier0 bench/huge.chg
```

Property filters use typed, memory-mapped property columns with bitmap and
dictionary indexes (`copperhound filter`, `POST /api/v1/nodes/filter`,
`/search`). On 20M nodes / 104M edges (`synth --users 16000000 --computers
3000000 --groups 1000000 --domains 8 --rich-props`), warm cache:

| filter | matches | columns | JSON scan¹ | CHQL² |
|---|---|---|---|---|
| enabled users with SPN in one domain | 52,721 | **2.4 ms** | 593 ms | 957 ms |
| computers with unconstrained delegation | 6,070 | **0.9 ms** | 30 ms | 36 ms |
| name contains `ser12345` (any case) | 1,111 | **8.9 ms** | 311 ms | 267 ms |
| enabled users, `lastlogon` < date | 2,010,085 | **16 ms** | 1,478 ms | 1,201 ms |
| computers with a given OS | 428,559 | **1.4 ms** | 469 ms | 453 ms |
| `description` contains a phrase | 35,542 | **0.7 ms** | 1,428 ms | 1,160 ms |
| `samaccountname` starts with | 11,111 | **4.0 ms** | 1,813 ms | 1,504 ms |

¹ the same filter evaluated per node from the stored JSON (no columns).
² `copperhound query` before property columns (`MATCH (u:User) WHERE …`); CHQL
now pushes such predicates down to the columns (docs/CHQL.md, "Predicate
pushdown").

Columns for that graph: 1.0 GB (+10% on a 10.7 GB graph), built in 9 s during
ingest, or in ~11 s on first use for graphs written by older versions.
