# CopperHound architecture

## Ingest pipeline

```
inputs (json / zip / dirs)
   │  zips extracted in parallel to a temp dir (base names only — no zip-slip)
   ▼
phase 1: scan (parallel per file AND within each file)
   mmap file → structural scanner → record byte ranges
   ▼
phase 2: parse (one flat parallel loop over ~4 MB batches from all files)
   serde_json::from_slice per record → Emitter
     • ids interned (sharded global interner + batch-local cache)
     • edges appended to batch-local Vec<Edge>
     • node updates (kind, name, flags) with a strength rank
     • DN-addressed edges (ldapdomaindump) deferred
     • OpenGraph files parsed whole; custom node kinds registered by name,
       name-addressed edge ends deferred
   ▼
merge (crates/ingest/src/merge.rs)
   source collection times → resolve DN edges → drop superseded owned
   edges → merge node attributes (newest wins; OpenGraph properties merge
   key by key) → number custom node kinds by name → resolve name-addressed
   edges → tag Tier Zero → canonical numbering (nodes by object id, extra
   edge kinds by name)
   ▼
ch-store::Graph::build
   parallel counting sort into CSR (atomic degree counts + scatter)
   per-row sort + dedup (giant hub rows sorted with par_sort)
   reverse CSR, string blobs, FNV-1a lookup indexes
   ▼
property columns (typed, dictionary-encoded, bitmap indexes)
   ▼
write: 17 column files in parallel, columns.bin/json, meta.json last
```

### Custom node kinds

Node kinds are one byte per node. Built-in kinds keep their `NodeKind`
discriminants (below 64); custom OpenGraph kinds use raw values 64–255, and
`meta.json` lists their names (`node_kinds`, index `i` ↔ raw `64 + i`).
`Graph::kind` returns `Unknown` for them, so built-in analyses treat them as
generic nodes; `Graph::kind_name` / `kind_raw` give the custom kind for
display, search, filters (`kind` property) and CHQL labels (resolved against
the graph's kind list at parse time).

### Structural scanner

Collector files are a single JSON document; naive parsing is single-threaded.
The scanner (`crates/ingest/src/scan.rs`) never builds values — it tracks
string boundaries (`memchr2` for `"`/`\`) and brace depth (`memchr3` for
`"`/`{`/`}`) to find each record's byte range.

Large arrays are scanned **speculatively in parallel**: each chunk guesses its
first record start (a `{` preceded by `}` `,`) and scans from there. Chunks are
stitched in order; a chunk is accepted only if its guessed start equals where
the previous chunk stopped, otherwise it is rescanned from that position. A
string containing `},{` can cause a wrong guess but never a wrong result
(tested in `parallel_matches_sequential_adversarial`).

### Why two phases

Spawning parse tasks from inside the scan loop (`rayon::scope`) used ~2 of 18
cores: tasks spawned from a long-running closure were not picked up promptly.
Scanning first, then parsing every batch in one flat `par_iter`, fixed load
balancing.

### Raw LDAP dumps (LDIF, AD Explorer)

`crates/ingest/src/ldap/`. Inputs are sniffed by content (`scan::detect`):
LDIF by its first `dn:` line, AD Explorer snapshots by header plausibility,
gzip by magic (LDIF inside is decompressed to the temp dir, then mapped like
any other file). Both readers yield `Entry` values (DN + raw values of ~70
known attributes; snapshot values are converted to LDAP text form) and share
one extractor:

```
LDIF: mmap → cut at blank lines into ~4 MB chunks      ┐
Snapshot: mmap → walk object sizes into ~4 MB chunks   ┘→ chunks (parallel)
pass 1 (index): DN hash → node id, domain NC → SID, host → computer,
                template CN → id, CA certs, LAPS schema GUIDs, crossRefs
pass 2 (extract): nodes + props + edges with references resolved via pass 1
```

DN references (`member`, `gPLink`, `msDS-OIDToGroupLink`, parents) never
reach the merge-time DN resolver; the index costs ≈ 20 B per object (64-bit
DN hash → `u32`), so memory is bounded by the interner and edges, as for
JSON. ACEs are decoded from the self-relative SD and mapped to SharpHound
right names by `ldap::sd::ace_rights` (mirrors SharpHoundCommon
`ACLProcessor`). `crates/ingest/tests/ldap.rs` tests equivalence with
SharpHound JSON of the same directory. The snapshot layout follows
ADExplorerSnapshot.py's community description (cited in
`ldap/adexplorer.rs`) and is verified against our own writer, not yet
against snapshots from AD Explorer itself.

### Merge semantics

`crates/ingest/src/merge.rs` combines many dumps imported at once: several
domains and forests, AD and Azure, repeated collections of one domain,
different collectors for one domain. This section describes policy `newest`
(default; `IngestOptions::merge_policy`, server setting `ingest.merge_policy`,
CLI `--merge`); `union` is the previous behaviour (flags OR'd, the last
record's properties, every edge kept).

**Sources and collection times.** Every input file and every zip entry is a
source. Its collection time is taken from, in order: the AD Explorer snapshot
header; a time field in the collector `meta` block (`collected`,
`collected_at`, `timestamp`, … — standard SharpHound / AzureHound meta blocks
have none); a `YYYYMMDDHHMMSS_` file-name prefix (SharpHound and
bloodhound-python name their files this way; the stamp is read as UTC, the
collectors write local time); the zip entry time; for LDIF / snapshots the
latest `whenChanged` in the file (a lower bound). File modification times are
never used (uploads and copies reset them), only reported (`file_mtime`). A
source without a collection time is *undated*.

**Node attributes.** A record from a newer dated source than the one that
defined the object so far replaces kind (strength rules as before), name and
flags (not OR'd); properties merge key by key with the newer value winning,
so keys only an older collector wrote survive. A later older record only fills
what is missing. Records with the same collection time, or with either side
undated, merge exactly like `union`. Flags derived after the merge (Tier Zero)
and operator marks (owned / Tier Zero, re-applied from `marks.json`) are
unaffected. Under `newest`, a node described by more than one source gets
`_sources`: manifest ids, newest first, at most 4 (`union` adds none, to stay
identical to the old behaviour).

**Edge ownership.** Parsers open a *section* `(owner, category)` before
emitting the edges of a record field and say whether the record *claims* the
category — carries it completely. The ingest-time `Edge::pad` (ignored by the
CSR build) stores the category and which endpoint is the owner; edges whose
owner is neither endpoint are left unowned. Claims are per-record
`(owner, category bitmask)` pairs. At merge, per node, the newest dated claim
rank and the categories claimed at that rank are computed (8 B per node); an
owned edge is dropped iff its owner has a claim of its category from a
strictly newer dated source. Hence:

- an edge stated by the newest data is never dropped (its own source is the
  newest for that owner and category);
- edges of objects absent from the newer collection, unowned edges, unclaimed
  categories and undated sources are never dropped;
- two copies of one collection produce the graph of one copy.

Session edges (`Sessions`, `PrivilegedSessions`, `RegistrySessions`) can be
kept from older collections within `session_window_secs` of the newest
session collection of the computer (server: `ingest.session_window_hours`,
default 0 = newest only).

Ownership by input format (category in parentheses). "Present" means the
field exists in the record; an empty list still claims (the collector read it
and found nothing). LDAP omits empty attributes, so LDIF / snapshot /
ldapdomaindump records claim only attributes they hold, and only when every
referenced DN was resolved.

| input | field / attribute | edges | claimed when |
|---|---|---|---|
| SharpHound | `Aces` | every ACE right (`GenericAll`, `WriteDacl`, `Owns`, `GetChanges*`, `AddKeyCredentialLink`, `ReadLAPSPassword`, `Enroll`, …) principal → object (`ACES`) | present |
| SharpHound | `Members` (group) | `MemberOf` member → group (`MEMBERS`) | present |
| SharpHound | `PrimaryGroupSID` | `MemberOf` object → group (`PRIMARY_GROUP`) | present |
| SharpHound | `AllowedToDelegate`, `AllowedToAct`, `HasSIDHistory` | `AllowedToDelegate`, `AllowedToAct`, `HasSIDHistory` (one category each) | present |
| SharpHound | `Sessions`, `PrivilegedSessions`, `RegistrySessions` | `HasSession` computer → user (one category each) | `Collected: true`; a session naming another computer is unowned |
| SharpHound | `LocalAdmins`, `RemoteDesktopUsers`, `DcomUsers`, `PSRemoteUsers`, `LocalGroups` (-544/-555/-562/-580) | `AdminTo`, `CanRDP`, `ExecuteDCOM`, `CanPSRemote` (one category per right) | `Collected: true` (bare v3 arrays never claim) |
| SharpHound | `ChildObjects` / `ContainedBy` | `Contains` container → child (`CHILDREN` on the container, `CONTAINED_BY` on the child) | present / non-null |
| SharpHound | `Links` | `GPLink` (`GP_LINKS`) | present |
| SharpHound | `Trusts` (domain) | `TrustedBy`, `SameForestTrust`, `CrossForestTrust`, `SpoofSIDHistory`, `AbuseTGTDelegation` (`TRUSTS`) | present |
| SharpHound ADCS | `EnabledCertTemplates`, `HostingComputer`, `CARegistryData.CASecurity`, `DomainSID`, `GroupLink` | `PublishedTo`, `HostsCAService`, CA rights (`ManageCA`, `ManageCertificates`, `Enroll`), `RootCAFor` / `NTAuthStoreFor`, `OIDGroupLink` | present (`CASecurity`: `Collected: true`) |
| SharpHound ADCS | `EnrollmentAgentRestrictions` | `DelegatedEnrollmentAgent` agent → template | never (unowned: the CA is no endpoint) |
| LDIF / AD Explorer | `nTSecurityDescriptor` | ACE rights incl. `Owns` (`ACES`) | SD present (absence may be missing read rights) |
| LDIF / AD Explorer | `member`, `member;range=0-…` | `MemberOf` (`MEMBERS`) | values present and all resolved |
| LDIF | `member;range=N-…`, N > 0 (continuation) | `MemberOf` (`MEMBERS`) | never: adds to the group's membership |
| LDIF / AD Explorer | `primaryGroupID`, parent DN, `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `sIDHistory`, `msDS-GroupMSAMembership`, `gPLink` | `MemberOf`, `Contains`, `AllowedToDelegate`, `AllowedToAct`, `HasSIDHistory`, `ReadGMSAPassword`, `GPLink` | present and resolved |
| LDIF / AD Explorer | `trustedDomain` objects | trust edges of the domain (`TRUSTS`) | any trust object of the domain |
| LDIF / AD Explorer | CA `certificateTemplates`, `dNSHostName`; issuance policy `msDS-OIDToGroupLink` | `PublishedTo`, `HostsCAService`, `OIDGroupLink` | present and resolved |
| LDIF / AD Explorer | root CA / NTAuth store | `RootCAFor`, `NTAuthStoreFor` | never (derived from the forest's domains in the input) |
| ldapdomaindump | `member`, `memberOf`, `primaryGroupID` | `MemberOf` (`MEMBERS` on the group, `MEMBER_OF` on the member, `PRIMARY_GROUP`) | non-empty |
| ldapdomaindump | parent DN | `Contains` | never |
| AzureHound | object records (`AZUser`, `AZGroup`, `AZServicePrincipal`, `AZApp`, `AZDevice`, `AZRole`, `AZSubscription`, `AZManagementGroup`, `AZResourceGroup`, `AZKeyVault`, `AZVM`, …) | `AZContains` from tenant / subscription / resource group, `AZRunsAs`, `AZManagedIdentity`, `AZNodeResourceGroup` (`AZ_NODE`) | always |
| AzureHound | `AZGroupMember` | `AZMemberOf` (`AZ_MEMBERS` on the group) | `members` array |
| AzureHound | `AZGroupOwner`, `AZServicePrincipalOwner`, `AZAppOwner` | `AZOwns` (`AZ_OWNERS` on the target) | `owners` array |
| AzureHound | `AZRoleAssignment` | `AZHasRole` principal → tenant-wide role (`AZ_ROLE_ASSIGN` on the role) | `roleAssignments` array; `AZAppAdmin` / `AZCloudAppAdmin` and scoped-role edges (`AZHasRole` to the scoped role node, `AZScopedTo`) are unowned |
| AzureHound | `AZRoleManagementPolicyAssignment` | `AZRoleApprover` (`AZ_ROLE_APPROVERS`) | approval required (a policy that stopped requiring approval does not clear older approvers) |
| AzureHound | `AZManagementGroupDescendant` | `AZContains` parent → child (`AZ_PARENT` on the child) | always |
| AzureHound | `AZFederatedIdentityCredential` | `AZAuthenticatesTo` (`AZ_FIC` on the app) | `fics` array |
| AzureHound | role filters (`AZKeyVaultOwner`, `AZVMAdminLogin`, … `AZSubscriptionUserAccessAdmin`) | `AZOwner`, `AZContributor`, `AZKeyVaultContributor`, `AZUserAccessAdministrator`, `AZAvereContributor`, `AZVMContributor`, `AZVMAdminLogin` (one category per list) | list present |
| AzureHound | `AZ<Resource>RoleAssignment` | `AZOwner`, `AZContributor`, `AZWebsiteContributor`, … (`AZ_RES_RBAC`) | `assignees` array |
| AzureHound | `AZRoleEligibilityScheduleInstance`, `AZAppRoleAssignment`, `AZKeyVaultAccessPolicy` | `AZRoleEligible`, `AZMG*`, `AZGetKeys` / `AZGetSecrets` / `AZGetCertificates` | never (one record per assignment, no complete list) |

Derived edges (`DCSync`, ADCS ESC*, `AZGlobalAdmin`, `AZResetPassword`,
hybrid `Synced*`, `EntraConnectCredentials`, `CoerceToTGT`, …) are computed
by post-processing from the merged graph, so they follow the newest data.

AD and Azure categories share bit numbers, since an object only ever has
records of one family. Categories and claims cost nothing per edge (the pad
field exists anyway) and 8 B per record; the merge adds one pass over the
claims and one parallel pass over the edges, only when at least two dated
collection times exist.

**Not handled** (by design; it would need guessing): an object deleted
between collections keeps the data of the last collection that saw it, since
absence from a newer dump can also mean a narrower collection scope. Use
`_sources` and the source manifest to judge staleness.

### Determinism

The same inputs give a byte-identical graph directory (bar the build time
recorded in `columns.json`) whatever the thread count, parse batch size,
input order, zip entry order or timing, so analysis on it (exposure, choke
points, plan, findings, reports) is identical too. Three things ensure this
(`crates/cli/tests/determinism.rs` checks them):

- **Sources** are numbered by relative file name, zip entry, then full path
  (`merge::canonical_source_order`), not by argument or discovery order, and
  parse outputs are merged in that order with each source's batches in
  record order. This fixes merge results that depend on record order
  (equal-time or undated records merge as a union where the last record's
  properties win; first kind hint wins; DN aliases) and the source ids in the
  manifest and in `_sources`.
- **Nodes** are renumbered by object id (byte order) after the merge
  (`merge::canonical_numbering`), because the interner hands out ids in
  first-sight order across parallel batches. Node ids drive analysis
  tie-breaks (equal choke objects in the plan, equal-flow choke edges, BFS
  order) and floating-point summation order, which otherwise changed run to run.
  Cost: one parallel sort of `(object id, node)` pairs (24 B per node,
  transient) plus an `O(nodes + edges)` remap (8 B per node). On a 10.8M
  node / 53M edge synthetic graph (18 threads) it takes ≈ 0.9 s of a ≈ 50 s
  ingest; the index build gets ≈ 1.2 s faster on the id-ordered nodes, so
  total ingest time and peak memory (16.1 GB) are unchanged within noise.
- **Collector-specific edge kinds** (rights CopperHound has no built-in kind
  for) are numbered by name instead of first sight.

Analysis itself is deterministic for a given graph: BFS levels are sorted,
flow and path counts are gathered per node in CSR order (never with
cross-thread reductions), and every ranking has a total tie-break (choke
edges: flow, then source id, target id, edge kind; plan: principals cut, then
node id — i.e. object id order).

Nothing persisted refers to node ids across graph generations: operator
marks, zones (selectors), saved queries, posture snapshots and alert state
key objects by object id, and the web UI's fix list re-resolves ids by
object id. Graphs written before canonical numbering still work, just
numbered differently.

### Allocation

The CLI uses mimalloc. With the Windows heap, millions of small parallel
allocations from serde serialised the parse phase.

## Store format

Directory of raw little-endian columns (see `crates/store/src/lib.rs` header).
Node ids are dense `u32`; edge offsets are `u64`, so edge counts are bounded
only by disk. `Graph::open` maps every column and validates lengths; no data
is read until queried.

Memory: `Graph::build` peaks at ≈ 12 B/edge (raw edges) + 8 B/edge (packed
adjacency) plus node columns. 1B edges ≈ 20 GB peak.

### Property columns (format 3)

Collector properties are kept per node as JSON text (`props.blob`): fine for
showing a node, hopeless for "every enabled user with an SPN in domain X" at
100M nodes. `crates/store/src/columns.rs` derives typed columns from that blob
once; `crates/store/src/filter.rs` evaluates filters over them.

**Files.** `columns.json` (manifest) and `columns.bin` (all sections, each
8-byte aligned, one memory map, zero-copy typed slices). The manifest records
`COLUMNS_VERSION` and the graph it belongs to (node count, `props.blob` and
`name.blob` lengths); a mismatch or a corrupt manifest means "rebuild".

**One column per property key**, lower-cased (CHQL keys are
case-insensitive); the first occurrence of a duplicate key wins, as in CHQL.
The type comes from the non-null values seen:

| type | sections |
|---|---|
| `bool` | `present` + `trues` roaring bitmaps |
| `int` / `float` | `present` bitmap, `ids` (`u32`, sorted; omitted when every node has a value), `values` (`i64` / `f64`) |
| `str` | `present`, `ids`, `codes` (`u8`/`u16`/`u32` by dictionary size), dictionary (`u64` offsets + blob) **sorted by ASCII-case-folded value**; ≤ 4096 distinct values add an **equality index** (one roaring bitmap per value) |
| `raw` | `present` only — lists, objects, mixed types; filters parse JSON, but only for nodes that have the key and survived cheaper conjuncts |
| `null` | key seen, always null |

Keys answered by node attributes or flags (`name`, `objectid`, `kind`, `id`,
`hasspn`, `admincount`, …; `enabled` is read from both) get no column. At
most 1024 keys (most frequent first) get columns; the manifest says whether
that covered all keys.

**Name search** reuses `name.blob` and `name.sorted` when names have no
lower-case ASCII (what ingest produces); otherwise a folded copy of the blob
and a folded sort order are added. Prefix/equality are binary searches in that
order; substring search is a `memchr::memmem` (SIMD) scan of the folded blob
in parallel id ranges, mapping hit offsets back to ids through `name.off`.
Nodes without a name (display = object id) are listed separately.

**Kind and flag bitmaps** are derived in memory on first use from
`nodes.kind` / `nodes.flags` (one parallel pass, tens of ms at 20M nodes);
flag bitmaps are dropped when an operator mark changes a flag.

**Evaluation** (`Graph::filter(&Filter) -> RoaringBitmap`). Leaves resolve to
bitmaps: kind/flag/bool bitmaps directly; string `=`/`IN`/`STARTS WITH` by
binary search in the folded dictionary, other string predicates by testing
each *dictionary entry* once, then OR-ing equality bitmaps or scanning the
code array; numeric predicates by a parallel scan of the value array; null
tests from `present`. `And` runs children cheapest-first (index < column scan
< per-row < JSON) and passes the running result down as the candidate set, so
JSON fallbacks only touch surviving candidates. `Not` is set difference.
Semantics are CHQL's `WHERE` semantics (string comparisons ignore ASCII case,
numeric strings coerce, lists match if any element matches, NOT includes
nulls). `Filter::matches` evaluates one node straight from JSON; it is the
oracle for the randomized tests in `crates/store/tests/filter.rs`, which cover
every operator, key type and boolean combination.

**Why not Arrow/Parquet.** arrow-rs + parquet add ~100 transitive crates and
a second in-memory model, Parquet is not mmap-able (pages are encoded and
compressed), and Arrow IPC would still need our own dictionary order, name
indexes and bitmap indexes on top. The graph store is already a directory of
raw little-endian columns; a few more sections in the same style plus
`roaring` (pure Rust, two small deps) keep open time at zero and the
dependency tree lean. An FST (`fst` crate) was considered for names, but the
sorted id order already answers prefix queries, and an FST cannot answer
substring search (the common autocomplete case); a SIMD scan of the name blob
takes a few ms per 10M names. A trigram index would answer substrings faster
but costs several bytes per name character.

**Cost** (20M nodes / 104M edges, 5.3 GB `props.blob`, `synth --rich-props`):
`columns.bin` 1.0 GB (+10% of the graph directory); built in 9 s at ingest
or ~11 s on first open of an older graph (two parallel JSON passes plus
dictionary sort; the build holds the finished columns in RAM once). Typical
filters run in 1–16 ms versus 0.3–1.8 s for the per-node JSON evaluation;
substring name search over 20M names takes ~9 ms. See [PERFORMANCE.md](PERFORMANCE.md#benchmarks).

**Compatibility.** Graphs written before format 3 open unchanged. On first
use (`Graph::columns`, which the server calls in the background after loading
a graph) columns are built from `props.blob` in parallel and persisted next to
the graph (write-to-temp + rename; manifest last), or kept in memory if the
directory is read-only. New graphs get columns at write time.

**CHQL adoption.** `crates/query/src/pushdown.rs` maps labels, inline
property maps and single-variable `WHERE` conjuncts onto `ch_store::Filter`
(`Cmp`, `IsNull`, `Truthy`, `Kind`, `And`/`Or`/`Not`), only where the store
agrees with CHQL on every input. A pattern's start candidates come from
`g.filter`, end-node predicates use bitmap membership, and residual
predicates still run in the evaluator. Store filters are evaluated only from
the query's coordinating thread: lazy store indexes initialise inside
`OnceLock`s with rayon, which must not be re-entered from a pool worker. The
store changes made to match CHQL and the remaining `enabled` difference are
listed in docs/CHQL.md, "Predicate pushdown".

## Engine

- **shortest_path** — level-synchronous bidirectional BFS between node sets;
  each step expands the side whose frontier has the lower total degree.
  Visited state lives in hash maps, so a query touches memory proportional to
  what it explores, not to graph size.
- **tier0_analysis** — reverse BFS from all Tier Zero nodes (distance to T0),
  forward σ path counts on the shortest-path DAG, then a reverse-order flow
  pass (Brandes-style) accumulating per-edge principal counts into a top-k
  heap. O(V + E), ~20 B/node scratch.
- **reach** — forward BFS blast radius.
- **remediation planner** (`ch_analysis::simulate::plan`) — a parallel reverse
  BFS from the zone, then the reachable attack graph is extracted once into
  compact CSR arrays. The *core* (nodes that have attackers) is renumbered in
  DFS preorder; leaves (most users) are kept out of the DFS. Each step runs
  Semi-NCA dominators on the core (one DFS + a path-compressed semidominator
  pass), gives every leaf its idom in parallel as the nearest common ancestor
  of its onward targets, sums dominator subtrees and severs the best choke
  object. Severing a choke object is equivalent to deleting it, so later steps
  only mark it dead and reuse every buffer. Results match the original
  from-scratch iterative planner exactly (kept as a test reference); a 3-step
  plan on 3.75M nodes / 19.7M edges takes ~1 s instead of ~25 s.
  `plan_weighted` keeps one such planner per zone; each step sums
  weight × dominator-subtree count per node over all zones (every candidate,
  not only each zone's top list), picks the best, and deletes it from every
  zone it is not a member of. Also checked against a from-scratch reference.

## Post-processing

`ch_ingest::build_graph` runs ingest → CSR build → post-processing passes
that need the built graph (`postprocess::PASSES`):
- `repl`: membership-aware `DCSync` and `SyncLAPSPassword` (replication
  rights propagated down `MemberOf` from their holders, per domain in
  parallel; memory is proportional to the holders' transitive members)
- `ad`: forest closure and `CoerceToTGT`
- `adcs`: CA chains and ESC edges
- `azure`: tenant role membership, and rights of object-scoped roles
- `hybrid`: AD ↔ Entra links, Entra Connect, Seamless SSO

Their derived edges are merged in one CSR rebuild (`Graph::with_extra_edges`).
After that, `postprocess::tier0_nodes` tags the hybrid Tier Zero objects (sync
accounts, the Entra Connect server, AZUREADSSOACC). Rules follow
`docs/research/adcs.md`, `docs/research/azurehound.md` and `docs/EDGES.md`.
Deliberate deviations from BloodHound CE are documented at the top of each pass.

Trust edges (`SameForestTrust`, `CrossForestTrust`, `SpoofSIDHistory`,
`AbuseTGTDelegation`) are emitted at ingest from SharpHound trust attributes.
Only the last two cross a forest boundary.

**Unified Tier Zero.** AD and Entra Tier Zero share the `TIER0` flag and form
one target set. `EdgeFilter::unified_tier0(false)` (server setting
`analysis.unified_tier0`) stops traversals crossing between AD and Azure
objects, measuring each realm separately.

Known simplifications:
- ESC8 (`CoerceAndRelayNTLMToADCS`) is not derived yet.
- Azure Tier Zero is the seed set: tenants, plus the GA / PRA / PAA / Partner
  Tier2 / Hybrid Identity Admin / Directory Synchronization Accounts roles.
  Role holders and privileged-permission service principals are not expanded
  into Tier Zero; they show up as exposed through their paths.
- ESC victims are not scoped to the enterprise CA's forest.
- Entra roles assigned over an administrative unit are kept as scoped role
  nodes but grant no derived edges: AzureHound does not collect AU membership.
  App- and object-scoped roles grant rights over that one object only
  (`docs/EDGES.md`, "Entra ID roles").
- `SyncLAPSPassword` is not emitted for principals that can also DCSync.
- `AZRoleApprover` is informational (not traversable); PIM policy settings are
  not stored on role nodes.

## Server

`ch-server` (axum) holds the active graph behind a `RwLock`; CPU-heavy
handlers run on the blocking pool. An ingest job rebuilds from all files in
`<data>/uploads`, writes a new graph directory, memory-maps it and swaps it in;
the previous graph is unmapped and deleted. Operator marks (`owned`, Tier Zero
add/remove) are stored by object id in `<data>/marks.json` and re-applied on
every load. Auth is multi-user with viewer/analyst/admin roles (Argon2id
passwords, 12 h sliding sessions, hashed `cht_` API tokens) and a JSONL audit
log; see `crates/server/src/auth.rs`.

After installing a graph the server loads its property columns on a
background thread (building and persisting them for format-2 graphs).
`/search` (exact → prefix → substring, case-insensitive) and
`POST /nodes/filter` use them; until they are ready, `/search` is prefix-only
and `/nodes/filter` waits.

## Roadmap

- **Open for a contributor:** ESC8 / NTLM-relay edges. Add the edge kind(s)
  in `crates/model/src/lib.rs` and a derivation pass under
  `crates/ingest/src/postprocess/`, alongside the existing ADCS passes.
- Graph generation id + query cancellation in the API; streaming results
- CHQL: multiple patterns, `ORDER BY`, `WITH`, undirected hops
- ~~Property columns for fast filtering at 100M+ nodes~~ — done (`columns.rs`).
- ~~CHQL: push single-variable `WHERE` conjuncts down to `Graph::filter`~~ —
  done (`crates/query/src/pushdown.rs`; exact semantics only, differential
  tests, `COPPERHOUND_VERIFY_PUSHDOWN`). Next: bitmaps for patterns started
  from bound variables when the input is large; a selectivity-based start
  node in the middle of a pattern for queries whose output does not depend
  on row order (`collect`, `LIMIT` without `ORDER BY`); per-node column
  reads instead of JSON for residual predicates.
- Property columns: external-memory build (today the build holds every
  column's values in RAM once, ≈ the size of `columns.bin`); list-of-string
  columns (SPNs, SID history) instead of the JSON fallback; trigram index if
  substring search must go below a few ms per 10M names
- ~~Raw LDIF / ldapsearch and ADExplorer snapshot ingest~~ — done (`ldap/`).
  Follow-ups: verify the snapshot reader on real AD Explorer files; follow
  `member;range=` for >1,500-member groups (needs the collector to page
  ranges); emit `OwnsLimitedRights` like BloodHound CE (`SyncLAPSPassword`
  is done); spill the DN index to disk beyond ~100M objects.
- External-memory CSR build when edges exceed RAM
- Snapshot diffing: track exposure and choke points over time
- SSO (OIDC/SAML); multi-user accounts are done
- Remediation planner (Semi-NCA version done, see Engine): truly decremental
  dominators so a step costs only the affected region instead of a pass over
  the core
