# CopperHound REST API (v1)

The web UI (served from `/`) is built on this API, and scripts can use it too. Paths are relative to
`/api/v1` unless they start with `/api/v2`. Bodies are JSON unless stated otherwise.

## Contents

1. [Overview and conventions](#1-overview-and-conventions)
   - [Authentication](#authentication) · [Signed requests (CH-HMAC)](#signed-requests-ch-hmac) · [Roles](#roles) · [Errors and status codes](#errors-and-status-codes) · [Graph generations and snapshots](#graph-generations-and-snapshots) · [Common objects](#common-objects) · [Endpoint index](#endpoint-index)
2. [Graph and data](#2-graph-and-data)
   - [Health and statistics](#health-and-statistics) · [Upload, ingest and jobs](#upload-ingest-and-jobs) · [Collection-aware merging and sources](#collection-aware-merging-and-sources) · [Environments](#environments-scope-by-domain--tenant) · [Nodes](#nodes) · [Search](#search) · [Property filters](#property-filters) · [Node and edge kinds](#node-and-edge-kinds) · [Edge composition](#edge-composition)
3. [Paths and queries](#3-paths-and-queries)
   - [Shortest paths](#shortest-paths) · [CHQL queries](#chql-queries) · [CHQL language summary](#chql-language-summary) · [Prebuilt queries](#prebuilt-queries) · [Saved queries](#saved-custom-queries)
4. [Risk analysis](#4-risk-analysis)
   - [Background analysis](#background-analysis) · [Tier Zero exposure and choke points](#tier-zero-exposure-and-choke-points) · [Findings](#findings) · [Finding history](#finding-history) · [Risk acceptance](#risk-acceptance) · [Zones](#zones-privilege-zones) · [Zone review](#zone-review) · [What-if simulation](#what-if-simulation) · [Remediation planner](#remediation-planner) · [Remediation hand-off](#remediation-hand-off-commands-and-tickets) · [Posture](#posture) · [Data quality](#data-quality)
5. [Reports, notifications, schedules and alerts](#5-reports-notifications-schedules-and-alerts)
   - [Reports](#reports) · [Notification channels](#notification-channels-admin) · [Scheduled reports](#scheduled-reports-admin) · [Change alerts](#change-alerts)
6. [Administration](#6-administration)
   - [Own account and API tokens](#own-account-and-api-tokens) · [Two-factor sign-in](#two-factor-sign-in-totp) · [Users](#users-admin) · [Audit log](#audit-log-admin) · [Settings and watch folder](#settings-and-watch-folder-admin) · [Built-in LDAP collector](#built-in-ldap-collector-admin) · [Collector clients](#collector-clients-admin) · [Node kind styles](#node-kind-styles) · [Network conduits](#network-conduits) · [Backup and restore](#backup-and-restore-admin) · [Database management](#database-management-admin)
7. [Single sign-on](#7-single-sign-on)
   - [Sign-in providers](#sign-in-providers) · [OpenID Connect](#openid-connect) · [SSO accounts](#sso-accounts) · [OIDC configuration](#oidc-configuration-admin) · [SAML 2.0](#saml-20) · [Break-glass](#break-glass-when-may-the-built-in-admin-use-its-password) · [SSO audit actions](#sso-audit-actions)
8. [BloodHound-compatible API (`/api/v2`)](#8-bloodhound-compatible-api-apiv2)
9. [Environment variables](#9-environment-variables)

## Quick start

Sign in, create an API token for scripts, upload collector output, rebuild the graph and ask
questions. Uses `curl` and `jq`; the demo data comes from
[`scripts/demo_data.py`](../scripts/demo_data.py) (fabricated).

```sh
CH=http://127.0.0.1:8090/api/v1

# 1. Sign in, then create a personal API token (shown once; store it in your secret manager).
SESSION=$(curl -s -X POST "$CH/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)
TOKEN=$(curl -s -X POST "$CH/me/tokens" -H "Authorization: Bearer $SESSION" \
  -H 'Content-Type: application/json' -d '{"name":"ci","expires_days":90}' | jq -r .token)
AUTH="Authorization: Bearer $TOKEN"

# 2. Upload collector output (.zip / .json / .ldif …) and rebuild the graph.
curl -s -H "$AUTH" -F "files=@hollowbrook.zip" "$CH/upload"
JOB=$(curl -s -X POST -H "$AUTH" "$CH/ingest" | jq -r .job_id)
until curl -s -H "$AUTH" "$CH/jobs/$JOB" | jq -e '.state == "done" or .state == "failed"' >/dev/null; do sleep 2; done

# 3. Shortest path from a principal to the nearest Tier Zero object.
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' "$CH/path" \
  -d '{"from":"SVC_WEB@HOLLOWBROOK.LOCAL","to_tier0":true}' | jq '[.edges[].kind]'
# → ["AllowedToDelegate","HasSession","MemberOf"]

# 4. A CHQL query with table output.
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' "$CH/query" \
  -d '{"query":"MATCH (u:User {hasspn:true, enabled:true}) RETURN u.name","limit":100}' | jq -c .rows

# 5. Findings, Tier Zero exposure and a Markdown report.
curl -s -H "$AUTH" "$CH/findings" | jq '.findings[] | {severity, title, count}'
curl -s -H "$AUTH" "$CH/tier0" | jq '{exposed_principals, total_principals}'
curl -s -H "$AUTH" "$CH/report?format=md" -o report.md
```

---

## 1. Overview and conventions

### Authentication

`POST /login` `{"username":"admin","password":"...","otp"?:"123456"}` →
`{"token":"...","username":"admin","role":"admin"}`.

Every other endpoint except `/health`, `/login` and the single sign-on endpoints under `/auth/`
(see [Single sign-on](#7-single-sign-on)) requires authentication; missing/invalid credentials →
`401 {"error":"unauthorized"}`. Three ways to authenticate a request:

- `Authorization: Bearer <session token>` — a session token from `/login` or from SSO (12 h sliding expiry).
- `Authorization: Bearer cht_…` — a personal API token (see [Own account and API tokens](#own-account-and-api-tokens)).
- `Authorization: CH-HMAC <token id>` — a request signed with an API token, without sending the token (see [Signed requests](#signed-requests-ch-hmac)).

The `/api/v2` compatibility API also accepts BloodHound's `bhesignature` request signing (see
[section 8](#8-bloodhound-compatible-api-apiv2)).

`POST /logout` revokes the bearer token → `{}`. Five failed logins lock the account for 5 minutes (`429`).
Accounts with two-factor sign-in enabled answer `401 {"error":"two-factor code required","mfa_required":true}`
until `otp` (a TOTP code or a recovery code) is sent with the password; see
[Two-factor sign-in](#two-factor-sign-in-totp). Wrong codes count towards the lockout. When single sign-on
policy refuses password sign-in for an account, `/login` returns `403` (see [Sign-in providers](#sign-in-providers)).

The built-in `admin` password comes from `COPPERHOUND_ADMIN_PASSWORD` (authoritative when set); if unset a
random one is generated at first start, printed to the log, and stored in the data directory.

### Signed requests (CH-HMAC)

A client can sign each request with an API token instead of sending it: the token never crosses the wire,
the request cannot be altered, and each signature is accepted once within ±5 minutes.

```
Authorization:       CH-HMAC <token id>
X-CH-Date:           2026-11-10T12:00:00Z
X-CH-Content-SHA256: <hex SHA-256 of the body>   (or UNSIGNED-PAYLOAD; bodies over 16 MiB must use it)
X-CH-Signature:      base64(HMAC-SHA256(SHA-256(token), METHOD "\n" PATH?QUERY "\n" X-CH-Date "\n" X-CH-Content-SHA256))
```

```python
import base64, datetime, hashlib, hmac, requests
TOKEN, TOKEN_ID, BASE = "cht_…", "<id from /me/tokens>", "https://copperhound.example.com"
def call(method, path, body=b""):
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    content = hashlib.sha256(body).hexdigest()
    msg = f"{method}\n{path}\n{date}\n{content}".encode()
    sig = base64.b64encode(hmac.new(hashlib.sha256(TOKEN.encode()).digest(), msg, hashlib.sha256).digest()).decode()
    return requests.request(method, BASE + path, data=body, headers={
        "Authorization": f"CH-HMAC {TOKEN_ID}", "X-CH-Date": date,
        "X-CH-Content-SHA256": content, "X-CH-Signature": sig, "Content-Type": "application/json"})
print(call("GET", "/api/v1/stats").json())
```

The HMAC key is the token's stored SHA-256, so a copy of `users.json` is enough to sign requests (as with
BloodHound's HMAC keys); bearer use of the token is not exposed by that file.

### Roles

Roles are resolved on every request, so changes apply immediately. Roles are ordered
`viewer` < `analyst` < `admin`; `uploader` is a separate, restricted role.

| Role | Can |
|---|---|
| `uploader` | upload-only (collector service accounts): `POST /upload`, `POST /ingest`, `GET /uploads`, `GET /jobs`, `GET /jobs/{id}`, the `/api/v2/file-upload…` endpoints, `/logout` and own account (`/me…`, incl. API tokens); nothing else, not even reads of the graph. The web UI shows only an upload page. Anything else → `403 {"error":"upload-only accounts may only upload files and start an ingest"}`. |
| `viewer` | every `GET` except the admin-only ones below (and `GET /alerts`, analyst), plus read-only analysis that takes a request body: `POST /query`, `DELETE /query/{id}`, `/path`, `/subgraph`, `/nodes/resolve`, `/nodes/filter`, `/simulate`, `/remediation-plan`, `/zones/membership`, `/report`, `/remediation/commands`; own account (`/me…`) and `/logout` |
| `analyst` | viewer + every other change not listed under admin: marks, saved queries, zones and zone review, uploads (`POST /upload`, `DELETE /uploads/{name}`), ingest, risk acceptance, creating tickets (`POST /tickets`), alert history (`GET /alerts`) |
| `admin` | analyst + `/users…`, `/audit`, `/settings…` (including `/settings/sso` and `/settings/saml`), `/database/…`, `/collectors…`, `/collect/…`, `/backup`, `/restore`, `/notify/…`, `/schedules…`, `/alerts/rules`, `DELETE /posture/{id}`, changing or testing `/tickets/targets`, `PUT /kind-styles`, `POST /api/v2/custom-nodes` |

Too low → `403 {"error":"this action requires the analyst role"}` (and a `denied` audit entry).
`GET /me` returns `permissions: {analyse, upload, modify, admin}` so a client can adapt its UI.

### Errors and status codes

Non-2xx responses: `{"error":"human readable message"}`. Unknown endpoints → `404 {"error":"no such endpoint"}`.

| Status | When |
|---|---|
| `202 {"status":"computing","progress":0-100}` | analysis endpoints while background analysis runs (see [Background analysis](#background-analysis)) |
| `400` | invalid request. Query syntax / semantic errors: `{"error":"...","position": <byte offset or null>,"code":"syntax"\|"semantic"}` |
| `401` | missing/invalid credentials, or two-factor code required |
| `403` | role too low, or policy refused |
| `404` | unknown object / endpoint |
| `408 {"error":"...","code":"timeout"}` | query timed out |
| `409` | conflict, e.g. a cancelled query (`{"error":"...","code":"cancelled"}`), a schedule already running, or an ingest job running during database clear |
| `429` | account locked after failed logins |

### Graph generations and snapshots

`/health` and `/stats` include `"generation": <u64>` (0 = no graph). It changes every time a new graph is
installed; node `id`s are only valid within one generation. `/path`, `/query` and `/subgraph` responses also
include `"generation"`.

Every snapshot (installed graph) has a stable string `snapshot_id` (also in `/health` and `/stats` as
`"snapshot_id"`). Posture history, findings and alerts refer to snapshots by this id.

### Common objects

**Node**
```json
{"id": 123, "objectid": "S-1-5-21-...-1104", "name": "ALICE@CORP.LOCAL", "kind": "User",
 "tier0": false, "owned": false, "enabled": true}
```
`id` is an integer, valid only within one [generation](#graph-generations-and-snapshots). `kind` is one of:
`User Group Computer Domain GPO OU Container CertTemplate EnterpriseCA RootCA AIACA
NTAuthStore IssuancePolicy AZTenant AZUser AZGroup AZApp AZServicePrincipal AZDevice
AZRole AZSubscription AZResourceGroup AZManagementGroup AZKeyVault AZVM AZAutomationAccount
AZContainerRegistry AZFunctionApp AZLogicApp AZManagedCluster AZVMScaleSet AZWebApp Unknown`,
or a custom OpenGraph kind name (see [Node and edge kinds](#node-and-edge-kinds)).

**Edge**
```json
{"src": 123, "dst": 456, "kind": "MemberOf"}
```

**GraphResult** — returned by anything that produces a subgraph.
```json
{"nodes": [Node], "edges": [Edge],
 "columns": ["n.name", "count"], "rows": [["ALICE@CORP.LOCAL", 3]],
 "paths": [[123, 456, 789]],
 "truncated": false, "elapsed_ms": 1.7}
```
`columns`/`rows` appear only for tabular query results, `paths` only for path results (node id sequences;
edges are in `edges`). `truncated` is true when a limit cut the result.

Other shared objects are defined where they are introduced: [Stats](#health-and-statistics),
[Job](#upload-ingest-and-jobs), [Source](#collection-aware-merging-and-sources),
[NodeDetail](#nodes), [PathRequest](#shortest-paths), [Tier0Report](#tier-zero-exposure-and-choke-points),
[Finding](#findings), [Zone](#zones-privilege-zones), [Token](#own-account-and-api-tokens),
[Delivery](#notification-channels-admin).

### Endpoint index

Minimum role per endpoint (see [Roles](#roles)). "public" = no authentication.

| Method | Path | Role | Section |
|---|---|---|---|
| GET | `/health` | public | [Health](#health-and-statistics) |
| POST | `/login` | public | [Authentication](#authentication) |
| POST | `/logout` | any | [Authentication](#authentication) |
| GET | `/stats` | viewer | [Health](#health-and-statistics) |
| POST | `/upload` | analyst (uploader) | [Upload](#upload-ingest-and-jobs) |
| GET | `/uploads` | viewer (uploader) | [Upload](#upload-ingest-and-jobs) |
| DELETE | `/uploads/{name}` | analyst | [Upload](#upload-ingest-and-jobs) |
| POST | `/ingest` | analyst (uploader) | [Upload](#upload-ingest-and-jobs) |
| GET | `/jobs`, `/jobs/{id}` | viewer (uploader) | [Upload](#upload-ingest-and-jobs) |
| GET | `/sources` | viewer | [Sources](#collection-aware-merging-and-sources) |
| GET | `/environments` | viewer | [Environments](#environments-scope-by-domain--tenant) |
| GET | `/nodes` | viewer | [Nodes](#nodes) |
| GET | `/nodes/{id}` | viewer | [Nodes](#nodes) |
| GET | `/nodes/{id}/edges` | viewer | [Nodes](#nodes) |
| POST | `/nodes/{id}/marks` | analyst | [Nodes](#nodes) |
| POST | `/nodes/resolve` | viewer | [Nodes](#nodes) |
| POST | `/subgraph` | viewer | [Nodes](#nodes) |
| GET | `/search` | viewer | [Search](#search) |
| POST | `/nodes/filter` | viewer | [Property filters](#property-filters) |
| GET | `/columns` | viewer | [Property filters](#property-filters) |
| GET | `/edge-kinds`, `/node-kinds` | viewer | [Kinds](#node-and-edge-kinds) |
| GET | `/edges/composition` | viewer | [Edge composition](#edge-composition) |
| POST | `/path` | viewer | [Shortest paths](#shortest-paths) |
| POST | `/query` | viewer | [CHQL queries](#chql-queries) |
| DELETE | `/query/{query_id}` | viewer | [CHQL queries](#chql-queries) |
| GET | `/queries` | viewer | [Prebuilt queries](#prebuilt-queries) |
| GET, POST | `/saved-queries` | viewer, analyst | [Saved queries](#saved-custom-queries) |
| PUT, DELETE | `/saved-queries/{id}` | analyst | [Saved queries](#saved-custom-queries) |
| GET | `/tier0` | viewer | [Tier Zero](#tier-zero-exposure-and-choke-points) |
| GET, PUT, DELETE | `/network` | viewer, admin | [Network conduits](#network-conduits) |
| GET | `/network/exposure` | viewer | [Network conduits](#network-conduits) |
| GET | `/findings`, `/findings/{id}` | viewer | [Findings](#findings) |
| GET | `/findings-involving` | viewer | [Findings](#findings) |
| GET | `/findings/{id}/history` | viewer | [Finding history](#finding-history) |
| PUT, DELETE | `/findings/{id}/acceptance` | analyst | [Risk acceptance](#risk-acceptance) |
| GET | `/findings/accepted` | viewer | [Risk acceptance](#risk-acceptance) |
| GET, POST | `/zones` | viewer, analyst | [Zones](#zones-privilege-zones) |
| PUT, DELETE | `/zones/{id}` | analyst | [Zones](#zones-privilege-zones) |
| GET | `/zones/{id}/members`, `/zones/{id}/exposure` | viewer | [Zones](#zones-privilege-zones) |
| POST | `/zones/membership` | viewer | [Zones](#zones-privilege-zones) |
| GET, POST | `/zones/{id}/review` | viewer, analyst | [Zone review](#zone-review) |
| POST | `/simulate` | viewer | [Simulation](#what-if-simulation) |
| POST | `/remediation-plan` | viewer | [Remediation planner](#remediation-planner) |
| POST | `/remediation/commands` | viewer | [Hand-off](#remediation-hand-off-commands-and-tickets) |
| GET, POST | `/tickets` | viewer, analyst | [Hand-off](#remediation-hand-off-commands-and-tickets) |
| GET, PUT | `/tickets/targets` | viewer, admin | [Hand-off](#remediation-hand-off-commands-and-tickets) |
| POST | `/tickets/targets/{id}/test` | admin | [Hand-off](#remediation-hand-off-commands-and-tickets) |
| GET | `/posture`, `/posture/diff` | viewer | [Posture](#posture) |
| DELETE | `/posture/{snapshot_id}` | admin | [Posture](#posture) |
| GET | `/quality` | viewer | [Data quality](#data-quality) |
| GET | `/report` | viewer | [Reports](#reports) |
| GET, PUT | `/notify/channels` | admin | [Channels](#notification-channels-admin) |
| POST | `/notify/channels/{id}/test` | admin | [Channels](#notification-channels-admin) |
| GET, POST | `/schedules` | admin | [Scheduled reports](#scheduled-reports-admin) |
| PUT, DELETE | `/schedules/{id}` | admin | [Scheduled reports](#scheduled-reports-admin) |
| POST | `/schedules/{id}/run` | admin | [Scheduled reports](#scheduled-reports-admin) |
| GET, PUT | `/alerts/rules` | admin | [Change alerts](#change-alerts) |
| GET | `/alerts` | analyst | [Change alerts](#change-alerts) |
| GET | `/me` | any | [Own account](#own-account-and-api-tokens) |
| PUT | `/me/password` | any | [Own account](#own-account-and-api-tokens) |
| GET, POST | `/me/tokens` | any | [Own account](#own-account-and-api-tokens) |
| DELETE | `/me/tokens/{id}` | any | [Own account](#own-account-and-api-tokens) |
| GET | `/me/mfa` | any | [Two-factor](#two-factor-sign-in-totp) |
| POST | `/me/mfa/setup`, `/me/mfa/enable`, `/me/mfa/disable` | any | [Two-factor](#two-factor-sign-in-totp) |
| GET, POST | `/users` | admin | [Users](#users-admin) |
| PUT, DELETE | `/users/{name}` | admin | [Users](#users-admin) |
| DELETE | `/users/{name}/tokens/{id}` | admin | [Users](#users-admin) |
| DELETE | `/users/{name}/mfa` | admin | [Two-factor](#two-factor-sign-in-totp) |
| GET | `/audit` | admin | [Audit log](#audit-log-admin) |
| GET, PUT | `/settings` | admin | [Settings](#settings-and-watch-folder-admin) |
| GET, PUT | `/collect/ldap` | admin | [LDAP collector](#built-in-ldap-collector-admin) |
| DELETE | `/collect/ldap/{id}` | admin | [LDAP collector](#built-in-ldap-collector-admin) |
| POST | `/collect/ldap/{id}/test`, `/collect/ldap/{id}/run` | admin | [LDAP collector](#built-in-ldap-collector-admin) |
| GET, POST | `/collectors` | admin | [Collector clients](#collector-clients-admin) |
| DELETE | `/collectors/{id}` | admin | [Collector clients](#collector-clients-admin) |
| GET, PUT | `/kind-styles` | viewer, admin | [Kind styles](#node-kind-styles) |
| GET | `/backup` | admin | [Backup](#backup-and-restore-admin) |
| POST | `/restore` | admin | [Backup](#backup-and-restore-admin) |
| POST | `/database/clear` | admin | [Database management](#database-management-admin) |
| GET | `/auth/providers` | public | [Sign-in providers](#sign-in-providers) |
| GET | `/auth/oidc/login`, `/auth/oidc/callback` | public | [OpenID Connect](#openid-connect) |
| POST | `/auth/oidc/exchange` | public | [OpenID Connect](#openid-connect) |
| GET, PUT | `/settings/sso` | admin | [OIDC configuration](#oidc-configuration-admin) |
| POST | `/settings/sso/test` | admin | [OIDC configuration](#oidc-configuration-admin) |
| GET | `/auth/saml/login`, `/auth/saml/metadata` | public | [SAML 2.0](#saml-20) |
| POST | `/auth/saml/acs` | public | [SAML 2.0](#saml-20) |
| GET, PUT | `/settings/saml` | admin | [SAML 2.0](#saml-20) |
| POST | `/api/v2/login` | public | [`/api/v2`](#8-bloodhound-compatible-api-apiv2) |
| GET | `/api/v2/file-upload` | viewer (uploader) | [`/api/v2`](#8-bloodhound-compatible-api-apiv2) |
| POST | `/api/v2/file-upload/start`, `/api/v2/file-upload/{id}`, `/api/v2/file-upload/{id}/end` | analyst (uploader) | [`/api/v2`](#8-bloodhound-compatible-api-apiv2) |
| POST | `/api/v2/custom-nodes` | admin | [Kind styles](#node-kind-styles) |

---

## 2. Graph and data

### Health and statistics

`GET /health` (public) →
```json
{"status": "ok", "graph_loaded": true, "generation": 4, "snapshot_id": "g-…", "version": "0.2.0",
 "limits": {"max_query_limit": 100000, "default_query_timeout_ms": 30000,
            "max_query_timeout_ms": 300000,
            "upload_extensions": [".json", ".zip", ".ldif", ".ldf", ".ldif.gz", ".dat"],
            "max_upload_bytes": null}}
```
`max_upload_bytes: null` = unlimited.

`GET /stats` → **Stats**
```json
{"nodes": 12500007, "edges": 65695752, "tier0": 7, "owned": 0,
 "node_kinds": {"User": 10000000}, "edge_kinds": {"MemberOf": 37155051},
 "loaded_at": "2026-11-05T12:00:00Z", "generation": 4, "snapshot_id": "g-…"}
```
When no graph is loaded yet, counts are 0 and maps empty.

### Upload, ingest and jobs

| Method | Path | Body / query | Response |
|---|---|---|---|
| POST | `/upload` | multipart, field `files` (any number of `.json` — collector or OpenGraph —, `.zip`, `.ldif`, `.ldf`, `.ldif.gz`, `.dat`) | `{"uploaded":["a.zip"]}` |
| GET | `/uploads` | | `[{"name","size","uploaded_at","in_graph","sources":[Source]}]` |
| DELETE | `/uploads/{name}` | | `{}` |
| POST | `/ingest` | | `{"job_id":"..."}` — rebuilds the graph from **all** uploads, then hot-swaps it |
| GET | `/jobs` | | `[Job]` newest first |
| GET | `/jobs/{id}` | | Job |

`/uploads` entries: `in_graph` = the file is part of the loaded graph; `sources` = the
[Source](#collection-aware-merging-and-sources) objects whose `file` is this upload (one per zip entry; `[]`
for uploads not yet ingested).

**Job**
```json
{"id": "j-3", "state": "queued|running|done|failed", "created_at": "...",
 "started_at": "...", "finished_at": "...", "message": "ingested 12.5M nodes",
 "report": {"files":4,"records":12500006,"nodes":12500007,"edges":65695752, "parse_errors":0, "seconds": 23.1,
            "merge_policy": "newest", "superseded_objects": 0, "superseded_edges": 0, "sources": 4}}
```
Running jobs include `"phase"` (`queued`, `extracting`, `scanning`, `parsing`, `merging`, `building`,
`post-processing`, `writing`, `loading`, `done`, `failed`) and `"percent"` (0–100, approximate). In `report`,
`sources` is a count. Jobs started by the watch folder carry `trigger: "watch"`.

Uploads can also arrive through the [watch folder](#settings-and-watch-folder-admin), the
[built-in LDAP collector](#built-in-ldap-collector-admin), [collector clients](#collector-clients-admin) and the
[BloodHound-compatible upload API](#8-bloodhound-compatible-api-apiv2).

### Collection-aware merging and sources

Background: [DATA.md](DATA.md#importing-multiple-dumps); rules: docs/ARCHITECTURE.md "Merge semantics".

**Merge settings.** `settings.ingest` (in `GET/PUT /settings`, admin; omitted fields take defaults):

| key | default | |
|---|---|---|
| `merge_policy` | `"newest"` | `"newest"`: per object the newest collection's record wins and edges it supersedes are dropped. `"union"`: plain union of all sources. |
| `session_window_hours` | `0` | `newest` only: also keep `HasSession` edges from collections up to N hours older than a computer's newest session data. 0–8760. |

Applies to the next ingest job (`POST /ingest` or the watch folder).

**Source** — one input file or zip entry of the loaded graph:

```jsonc
{"id": 3,                                         // sources are numbered by file, entry, then full path
 "file": "20240201093000_BloodHound.zip",        // path relative to the uploads dir (the archive for zip entries)
 "entry": "20240201093000_users.json",           // zip entry, or null
 "format": "sharphound",                          // sharphound | azurehound | ldapdomaindump | ldif | adexplorer | json (unparsed)
 "kind": "users",                                 // object type of the file when known, else null
 "domains": ["CORP.LOCAL"],                       // AD domain names / Azure tenant ids in the records (≤ 64)
 "collected_at": "2024-02-01T09:30:00Z",          // null = undated: merged as a plain union
 "collected_at_unix": 1706779800,
 "collected_at_source": "filename",               // snapshot | meta | filename | zip-entry | whenchanged | null
 "file_mtime": "2024-02-03T10:00:00Z",            // informational only, never used for ordering
 "records": 1200, "objects": 1200, "edges": 5400, // records parsed, object records, edges emitted
 "superseded_objects": 0,                         // object records overridden by a newer source
 "superseded_edges": 0,                           // edge records dropped: a newer record of the owner
                                                  // claims their category (includes edges the newer
                                                  // record states again, which stay in the graph)
 "parse_errors": 0}
```

`collected_at_source`: `snapshot` = AD Explorer header time, `meta` = a time field in the collector `meta`
block, `filename` = `YYYYMMDDHHMMSS_` name prefix (UTC), `zip-entry` = archive entry time, `whenchanged` =
latest LDAP `whenChanged` in the file (lower bound).

`GET /sources` (viewer) → sources of the **loaded** graph:
```json
{"generation": 4, "merge_policy": "newest", "superseded_objects": 10230,
 "superseded_edges": 81211, "sources": [Source]}
```
For a graph built without source metadata (an older graph directory): `merge_policy` and the counters are
`null`, `sources: []`.

**Node provenance.** With `merge_policy: "newest"`, a node described by more than one source has
`"_sources": [3, 0]` in its properties (never under `"union"`): source ids (index into `sources`), newest
collection first, at most 4, valid for the graph generation they came with.

**Graph directory.** `meta.json` carries `"ingest": {"merge_policy", "superseded_objects", "superseded_edges",
"sources": [Source]}` (absent in older graphs).

### Environments (scope by domain / tenant)

`GET /environments` → `[{"id": "<objectid>", "name", "kind": "ad|tenant", "objects"}]`. An object belongs to
the domain of its SID (else its `domainsid`) or the tenant that `AZContains` it (else its `tenantId`).

`GET /findings?env=<id>`, `GET /findings/{id}?env=<id>` and `GET /report?env=<id>` keep only finding items in
that environment: the target of edge items (the source when the target has none), the object of node items.
Findings left without items disappear; per-finding exposure figures are graph-wide and are omitted in a
scoped view. The scoped `/findings` response carries `"environment": {…}`; a scoped report is titled after
the environment unless a title is given.

### Nodes

| Method | Path | Body / query | Response |
|---|---|---|---|
| GET | `/nodes/{id}` | | NodeDetail (below) |
| GET | `/nodes/{id}/edges` | `dir=out\|in`, `kind?`, `limit?=500` | GraphResult (the node + neighbours) |
| GET | `/nodes` | `ids=1,2,3` | `[Node]` (unknown ids omitted, max 5000) |
| POST | `/nodes/resolve` | `{"objectids": [...]}` | `[Node]` (unknown omitted, max 5000) |
| POST | `/subgraph` | `{"ids": [...]}` | GraphResult with those nodes and every edge (any kind) among them (max 5000 ids), plus `generation` |
| POST | `/nodes/{id}/marks` | `{"owned":true?,"tier0":false?}` | Node (persisted across re-ingest by objectid) |

**NodeDetail** = Node plus
```json
{"properties": {"name":"...","pwdlastset":1699999999, "...": "..."},
 "flags": ["enabled","admincount"],
 "in_degree": 4, "out_degree": 12,
 "edge_counts": {"out": {"MemberOf": 3}, "in": {"GenericAll": 1}}}
```
`properties` may include `_sources` (see [node provenance](#collection-aware-merging-and-sources)).

### Search

`GET /search?q=&kind=&limit=20` → `[Node]`. Exact name / objectid matches come first, then name-prefix
matches, then name-substring matches; within each group shorter names first, then alphabetically. All
matching ignores ASCII case. `kind` also accepts custom OpenGraph kind names.

Substring matches need the property columns, which build in the background after a graph is loaded (or
upgraded from an older format); until `/columns` reports `ready`, `/search` is prefix-only.

### Property filters

`GET /columns` → `{"ready":false}` while property columns load, then
`{"ready":true,"origin","complete","columns":[{"key","type","count","distinct","eq_index"}]}`.

`POST /nodes/filter` `{"filter": Filter, "limit"?: 100, "offset"?: 0}` →
`{"total","offset","nodes":[Node],"filter_ms","elapsed_ms"}`.

It evaluates a Filter over every node using typed property columns and indexes (see `docs/ARCHITECTURE.md`)
and returns matches in node-id order, paged by `limit` (max 10 000) / `offset`. A Filter is a JSON tree:

```json
{"and": [
  {"kind": ["User"]},
  {"truthy": "enabled"},
  {"truthy": "hasspn"},
  {"cmp": {"key": "domain", "op": "eq", "value": "CORP.LOCAL"}},
  {"not": {"cmp": {"key": "lastlogon", "op": "gt", "value": 1700000000}}}
]}
```

| node | meaning |
|---|---|
| `{"const": true}` | all / no nodes |
| `{"kind": "User"}` or `{"kind": ["User","Computer"]}` | node kind |
| `{"cmp": {"key","op","value"}}` | `op`: `eq` `ne` `lt` `le` `gt` `ge` `starts_with` `ends_with` `contains` `in` (or `=` `<>` `<` `<=` `>` `>=`) |
| `{"is_null": {"key", "null?": true}}` | property absent / null (`"null": false` = present) |
| `{"truthy": key}` | true, non-zero, non-empty |
| `{"and": [...]}`, `{"or": [...]}`, `{"not": {...}}` | boolean combinations |

Keys are case-insensitive. `name`, `objectid`, `kind`, `id` and the flags (`enabled`, `tier0`, `owned`,
`admincount`, `highvalue`, `unconstraineddelegation`, `dontreqpreauth`, `hasspn`) are node attributes; any
other key is a collector property. Comparison semantics are CHQL's (string comparisons ignore ASCII case,
numeric strings compare as numbers, a list matches if any element does, `NOT` includes nulls).

### Node and edge kinds

- `GET /edge-kinds` → `[{"name","traversable","category","count","help","composite"}]`; `help` is
  `{"description","abuse","remediation"}` for derived / hybrid / trust kinds (see `docs/EDGES.md`), else
  `null`; `composite` is true for kinds that [`/edges/composition`](#edge-composition) can explain.
- `GET /node-kinds` → `[{"name","category","count"}]`; custom OpenGraph kinds follow the built-in ones with
  `"category": "Custom", "custom": true`.

`category` is one of `"Active Directory"`, `"ADCS"`, `"Azure"`, `"Hybrid"` (node kind `Unknown` has category
`"Other"`). `count` is the number of edges / nodes of that kind in the loaded graph (0 if none).

Shared colours and icons per kind: see [Node kind styles](#node-kind-styles).

### Edge composition

`GET /edges/composition?src=12&dst=3&kind=ADCSESC1` explains why an edge derived by post-processing exists
(`/edge-kinds` marks these kinds `"composite": true`): DCSync, SyncLAPSPassword, CoerceToTGT, GoldenCert, the
ADCSESC* edges, the derived Entra role edges (AZGlobalAdmin, AZAddMembers, AZResetPassword, AZMG*, …) and the
hybrid edges. `400` for kinds that are not derived, `404` when the edge is not in the graph.

The response is a GraphResult holding the collected edges the rule used (group membership chains, rights,
the CA chain to the domain, role assignments, trusts) plus:
```json
{"edge": {"src": 12, "dst": 3, "kind": "ADCSESC1"},
 "notes": ["Template ESC1@CORP.LOCAL: enrolleesuppliessubject = true, ..."],
 "complete": true}
```
`notes` hold facts that are not edges (template and CA flags, DC registry values, implicit Authenticated
Users membership, sync attributes). ADCS edges are explained by replaying the ADCS pass and recording the
rule match (template, CA, victim) that emitted the edge. `complete` is false when part of the rule is no
longer in the loaded graph.

---

## 3. Paths and queries

### Shortest paths

`POST /path` PathRequest → GraphResult with one path in `paths` (or empty if none), plus `hops` and
`generation`.

**PathRequest**
```json
{"from": 123, "to": 456, "to_tier0": false, "to_zone": null, "exclude": ["HasSession"], "all_edges": false, "all": false}
```
- `from`/`to` may be ids or names/objectids (strings).
- `to` is ignored when `to_tier0`. `"to_zone": "<zone id>"` targets the nearest member of that
  [zone](#zones-privilege-zones) and overrides `to`/`to_tier0`.
- `exclude` lists edge kinds not to follow; `all_edges` follows non-traversable kinds too.
- With `"all": true` (all shortest paths) the result holds every shortest path as one subgraph (up to
  2,000 relationships; `truncated` when capped), `paths`/`hops` give one of them, and `all_paths` =
  `{"length", "nodes", "edges", "truncated"}` (`nodes` / `edges` are counts).
- Whether Tier Zero targets span AD and Entra ID follows the `analysis.unified_tier0`
  [setting](#settings-and-watch-folder-admin).
- With `"network": true` the path must also pass the [network conduits](#network-conduits): the
  result is the shortest path the firewall rules allow (one path; `all` is ignored), with `"network": true`
  and `"zones"` (the `net_zone` of each path node, `null` for none). 400 when no conduits are configured.

Results include `"hops": [{"src","dst","kind"}]` in path order (one entry per hop, even when several kinds
connect the same pair).

### CHQL queries

`POST /query` `{"query":"...","limit":1000,"timeout_ms"?:30000,"query_id"?:"..."}` → GraphResult (plus
`generation`).

- `timeout_ms` is optional (default and maximum in `/health` `limits`); `query_id` is a client-chosen string
  (≤ 64 chars).
- `DELETE /query/{query_id}` cancels a running query → `{"cancelled": true|false}`.
- Errors: `400` (syntax / semantic, with `position`), `408` (timeout), `409` (cancelled); bodies as in
  [Errors and status codes](#errors-and-status-codes).
- GraphResults that contain paths include `"path_hops"`: one hops list per entry of `paths`.

### CHQL language summary

A read-only Cypher dialect compiled to native graph operations. The full reference — grammar, semantics,
functions, limits and the **Cypher compatibility table** — is in [CHQL.md](CHQL.md); most BloodHound CE /
legacy queries run unchanged.

```
[OPTIONAL] MATCH <pattern>[, <pattern>…] [WHERE <expr>]        (repeatable)
[UNWIND <expr> AS x]
[WITH [DISTINCT] <items> [ORDER BY …] [SKIP n] [LIMIT n] [WHERE <expr>]]
RETURN [DISTINCT] <items> [ORDER BY <expr> [ASC|DESC], …] [SKIP n] [LIMIT n]
[UNION [ALL] <query>]
```

Patterns
```
(n)                                   any node
(n:User)                              label (kind); (n:User|Computer) either; (n:Group:Base) all
(n:User {name:'ALICE@CORP.LOCAL'})    inline property equality
(a)-[:MemberOf]->(b)                  one hop; (a)<-[:AdminTo]-(b) reverse; (a)-[:X|Y]-(b) undirected
(a)-[r:AdminTo|CanRDP]->(b)           several edge kinds, bound to r
(a)-[:MemberOf*1..]->(g)              variable length (default *1..∞), any direction
(a)-->(g)-->(c), (c)-->(d)            chains; comma patterns / MATCH clauses join on shared variables
p = shortestPath((a)-[*1..]->(b))     one shortest path per start node a (per pair when both bound)
p = allShortestPaths((a)-[*1..]->(b)) union of all shortest paths from a-set to b-set
```
A fixed hop without edge kinds follows any kind; variable-length hops and path functions follow traversable
kinds.

Expressions
```
n.prop = 'x'   <>  <  <=  >  >=   + - * / % ^
n.name STARTS WITH 'ADM' | ENDS WITH | CONTAINS | =~ '(?i)adm.*'   (case-insensitive)
n.prop IN ['a','b']       n.prop IS NULL | IS NOT NULL
n:Computer                (label test)      NOT (a)-[:MemberOf]->(b)   (pattern predicate)
AND OR XOR NOT ( )        CASE … END        [x IN list WHERE … | …]    any/all/none/single(…)
toLower toUpper coalesce size length type labels nodes relationships id exists split substring …
count(*) count(DISTINCT x) collect min max sum avg
```
Literals: `'string'` / `"string"`, integers, floats, `true`, `false`, `null`, lists.

**Relative time.** `days_ago(n)` is a numeric literal equal to the Unix epoch seconds `n` days before now,
e.g. `MATCH (u:User {enabled:true}) WHERE u.lastlogontimestamp < days_ago(90) RETURN u`.

Built-in properties (fast, columnar): `name`, `objectid`, `kind`, `tier0`, `owned`, `enabled`, `admincount`,
`highvalue`, `unconstraineddelegation`, `dontreqpreauth`, `hasspn`. Any other property is read from the
collector's raw properties.

RETURN: any expressions, `AS` aliases, `*`. Node/edge/path values (also in lists, e.g. `collect(n)`) fill
`nodes`/`edges`/`paths`; scalar items produce `columns`/`rows`.

Examples
```
MATCH (u:User {dontreqpreauth:true}) RETURN u
MATCH p = shortestPath((u:User {name:'ALICE@CORP.LOCAL'})-[*1..]->(t {tier0:true})) RETURN p
MATCH p = allShortestPaths((g:Group {name:'DOMAIN USERS@CORP.LOCAL'})-[*1..]->(t {tier0:true})) RETURN p
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.tier0 RETURN c.name
MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN count(u)
MATCH (n {owned:true}), (m:Group) WHERE m.objectid ENDS WITH '-512' MATCH p = shortestPath((n)-[*1..]->(m)) RETURN p
MATCH (n)-[:AdminTo]->(c:Computer) WITH c, count(n) AS admins RETURN c.name, admins ORDER BY admins DESC LIMIT 10
```

### Prebuilt queries

`GET /queries` → `[{"id","name","category","description","query","tags"}]` — `id` is a stable slug, `tags` a
string array. ~80 queries in categories such as Domain Information, Dangerous Privileges,
Kerberos, Delegation, ACL Abuse, Sessions & Lateral Movement, GPO & OU, Hygiene, Shortest Paths, Tier Zero,
Owned, ADCS, Azure / Entra ID, Azure Resources, Hybrid.

### Saved (custom) queries

Persisted server-side in the data directory.
- `GET /saved-queries` → `[SavedQuery]`
- `POST /saved-queries` `{name, category?, description?, query}` → SavedQuery
- `PUT /saved-queries/{id}` (same body) → SavedQuery
- `DELETE /saved-queries/{id}` → `{}`

`SavedQuery = {"id","name","category","description","query","created_at","updated_at"}`. `category` defaults
to `"Custom"`. Query text is validated (parsed) on save → `400` with `position` on syntax errors.

---

## 4. Risk analysis

### Background analysis

Analysis runs in the background after a graph is installed; dependent endpoints return
`202 {"status": "computing", "progress": 0-100}` until ready. Results are tied to the graph's `snapshot_id`.

### Tier Zero exposure and choke points

`GET /tier0?top=25` → Tier0Report (cached until the graph or marks change; changing
`analysis.unified_tier0` also drops the cache).

**Tier0Report**
```json
{"tier0_nodes": 7, "max_depth": 16, "exposed_principals": 11337124,
 "exposure": [{"kind":"User","with_path":9989945,"total":10000000}],
 "choke_points": [{"src": Node, "dst": Node, "kind": "MemberOf", "flow": 2183032.6}],
 "elapsed_ms": 8050}
```
The same shape is returned per zone by [`/zones/{id}/exposure`](#zones-privilege-zones). Mark objects as Tier
Zero with [`POST /nodes/{id}/marks`](#nodes).

### Findings

- `GET /findings[?env=<id>]` → `{"status":"ready","snapshot_id":"...","computed_ms": n, "summary": {"critical":n,"high":n,"medium":n,"low":n}, "summary_all": {…}, "accepted_count": n, "findings":[Finding]}`
- `GET /findings/{id}?offset=0&limit=100[&env=<id>]` → Finding plus `"items": [Item]`, `"total": n`, and `"graph": GraphResult` (up to 500 items drawn); `limit` ≤ 5000
- `GET /findings-involving?node=<id>` → `[{"id","title","severity","items": n}]` (202 while computing)

```jsonc
Finding = {"id":"dcsync-non-tier0","title":"Non-Tier Zero principals can DCSync",
  "severity":"critical|high|medium|low","category":"Active Directory|ADCS|Azure|Hybrid",
  "kind":"edges|nodes","count": 3,
  "exposure": {"principals_cut": 1234, "percent_of_exposed": 12.5} | null,
  "description":"...","impact":"...","remediation":"...","mitre":["T1003.006"],
  "query":"CHQL used to detect it",
  "accepted": {…} | null}
Item (kind=edges) = {"src": Node, "dst": Node, "kind": "DCSync"}
Item (kind=nodes) = {"node": Node}
```
`exposure` (edge findings only): how many principals would lose every path to Tier Zero if all of the
finding's edges were removed; `null` when not applicable. Findings with `count: 0` are omitted. For
`accepted`, `summary`, `summary_all` and `accepted_count` see [Risk acceptance](#risk-acceptance); for `env`
see [Environments](#environments-scope-by-domain--tenant).

### Finding history

`GET /findings/{id}/history` → `{"id", "points": [{"snapshot_id", "created_at", "count"}] (oldest first), "latest_change": {"from", "to", "from_at", "to_at", "added", "removed", "added_sample": [label], "removed_sample": [label]} | null}`
— the finding's item count in every posture snapshot and what appeared / disappeared between the last two
snapshots with stored items (up to 50 labels each).

### Risk acceptance

- `PUT /findings/{id}/acceptance` (analyst) `{"reason": "…", "expires_days"?: 90}` → `{"id", "acceptance": {"reason", "accepted_by", "accepted_at", "expires_at"?}}`
- `DELETE /findings/{id}/acceptance` (analyst) → `{"id", "acceptance": null}`; the finding is open again
- `GET /findings/accepted` → `[{"id", "active", "acceptance"}]` (expired ones listed with `"active": false`)

Accepted findings are still computed and returned by `/findings` (with `"accepted": {…}`; `null` when open).
`summary` counts open findings only (`summary_all` counts every finding, `accepted_count` the accepted ones);
new-finding alerts skip them; the report lists them under "Accepted risks" instead of the findings tables,
and its grade uses open findings. Posture snapshots keep measuring every finding. An acceptance lapses at
`expires_at`. Stored in `<data>/accepted_risks.json`.

### Zones (privilege zones)

A zone is a set of target objects. The built-in zone `tier0` holds objects flagged Tier Zero and cannot be
edited or deleted. A custom zone's members are the node results of its CHQL **selector**.

- `GET /zones` → `[Zone]`
- `POST /zones` `{name, description?, selector, color?}` → Zone (selector parsed and run; `400` with `position`/`code` on error)
- `PUT /zones/{id}` same body → Zone
- `DELETE /zones/{id}` → `{}`
- `GET /zones/{id}/members?offset=0&limit=200` → `{"total": n, "items": [Node]}` (`limit` ≤ 20000)
- `GET /zones/{id}/exposure?top=25` → Tier0Report shape (see [`/tier0`](#tier-zero-exposure-and-choke-points)) for that zone
- `POST /zones/membership` `{"ids": [1, 2]}` → `{"1": ["tier0", "z-ab12"]}` (max 20000 ids; nodes in no zone omitted)

`Zone = {"id","name","description","selector","color","builtin": bool,"member_count": n}`. `color` is a CSS
hex string (default chosen by server).

Zones are also targets for [`/path`](#shortest-paths) (`to_zone`), [`/simulate`](#what-if-simulation) and the
[remediation planner](#remediation-planner).

### Zone review

Each object a custom zone's selector matches is `pending` until an analyst certifies it or revokes it.
Revoked objects are left out of `member_count`, `/members`, exposure, plans and zone paths while the selector
still matches them; objects matched later start as pending. Decisions are keyed by object id
(case-insensitive), so they survive re-ingests. Not available for `tier0` (use marks).

- `GET /zones/{id}/review?status=pending|certified|revoked&offset=0&limit=200` →
  `{"zone", "counts": {"pending","certified","revoked"}, "total", "offset", "items": [{"node": Node, "status", "decision": {"status","by","at","note"?} | null}]}`
  (`total` counts the filtered rows)
- `POST /zones/{id}/review` (analyst) `{"objectids": [..], "status": "certified"|"revoked"|"pending", "note"?}` →
  `{"zone","updated": n,"status"}`; `pending` clears the decision. Up to 10 000 ids per call.

### What-if simulation

`POST /simulate`
```json
{"zone": "tier0",
 "remove_edges": [{"src": 12, "dst": 34, "kind": "MemberOf"}],
 "remove_kinds": ["HasSession"],
 "remove_nodes": [56],
 "add_targets": [78]}
```
All fields optional (`zone` defaults to `tier0`). Response:
```json
{"before": {"exposed_principals": n, "exposure":[KindExposure], "max_depth": d},
 "after":  {"exposed_principals": n, "exposure":[KindExposure], "max_depth": d},
 "reduction": n, "reduction_percent": 12.3, "elapsed_ms": 45.1}
```
`KindExposure` is an entry of Tier0Report `exposure` (`{"kind","with_path","total"}`).

### Remediation planner

`POST /remediation-plan` `{"zone":"tier0","steps":10,"fixed_kinds":["Contains"],"protect_target_membership": true, "respect_fix_cost": true, "live_first": false}`

Each step picks the **choke object** whose fix cuts the most principals off from the zone *entirely*,
computed exactly with a dominator tree over all attack paths. The fix is to remove the choke object's onward
attack edges (listed in `edges`; usually one or a few, e.g. a group's `AdminTo` on a Tier Zero server). The
plan is recomputed after every step. `fixed_kinds` are never proposed
for removal; with `protect_target_membership` (default true) members of zone groups count as part of the
zone, so the planner never proposes removing admins from admin groups. With `respect_fix_cost` (default true)
the `fix_cost` node property applies: choke objects with an edge to or from a `fixed` object are skipped, and
steps touching a `window` object have `"needs_window": true`; `live_first` puts every step without a window
first ([OT.md](OT.md#fix-cost)). Response:
```json
{"baseline": n, "truncated": false, "elapsed_ms": n,
 "steps": [{"node": Node, "edges": [{"src": Node, "dst": Node, "kind": "AdminTo"}],
            "principals_cut": n, "exposed_after": n, "cumulative_reduction_percent": p, "needs_window": false}]}
```
`edges` is capped at 50 per step (`edge_count` gives the full number). Runs synchronously; may take seconds
on very large graphs (honours `timeout_ms`, default 120000).

### Remediation hand-off (commands and tickets)

Edges are given by object id (`EdgeRef = {"src": "<objectid>", "kind": "MemberOf", "dst": "<objectid>"}`,
names also resolve), up to 200 per call.

- `POST /remediation/commands` `{"edges": [EdgeRef]}` (viewer) →
  `{"items": [{"src": Node, "dst": Node, "kind", "guidance": "<edge help remediation>"|null, "command": "<PowerShell>"|null}], "missing": [EdgeRef]}`.
  Commands remove that one relationship, identifying objects by SID / object id: AD group membership, local
  group membership (AdminTo, CanRDP, CanPSRemote, ExecuteDCOM), explicit ACEs for each ACL edge (filtered by
  the right and its property / extended-right GUID), ownership, constrained and resource-based delegation,
  SID history, gMSA readers, GPO links, certificate template enrolment, Entra group membership and
  ownership, directory role assignments and PIM eligibility, Microsoft Graph app role grants and Azure RBAC
  role assignments. `null` for edges with no single scripted fix (derived, structural, CA-side). Review
  before running: a right that comes from a GPO, an inherited ACE or a parent Azure scope must be fixed
  there.
- `GET /tickets/targets` (viewer) → `[TicketTarget]` with `token_set` instead of the token.
- `PUT /tickets/targets` (admin) `{"targets": [TicketTargetIn]}` replaces the list.
  `TicketTargetIn = {"id"?, "name", "type": "jira"|"servicenow"|"webhook", "enabled", "url", "username"?, "token"?, "project"?, "issue_type"?, "table"?, "labels"?, "fields"?}`;
  `token` absent keeps the stored one, `""` clears it.
  - **Jira** (Cloud or Data Center): `url` is the site, `username` the account email with an API token
    (Basic) or empty with a personal access token (Bearer); `project` required, `issue_type` default `Task`.
    Issues are created with `POST /rest/api/2/issue`; `fields` are merged into the issue fields.
  - **ServiceNow**: `url` is the instance, `username` / `token` a user and password, `table` default
    `incident`; `fields` (e.g. `assignment_group`) are merged into the record.
  - **Webhook**: JSON `{"event": "remediation.ticket", "title", "note", "description", "items": [...], "link"}`,
    with `X-CopperHound-Signature: sha256=<hmac>` when `token` is set. A response
    `{"key"|"id"|"number", "url"?}` is used as the ticket reference.
- `POST /tickets/targets/{id}/test` (admin) → `{"ok": true, "detail"}` or `{"ok": false, "error"}` (Jira
  `GET /rest/api/2/myself`, ServiceNow a one-row table read, webhook a `test` event).
- `POST /tickets` (analyst) `{"target", "edges": [EdgeRef], "title"?, "note"?, "split"?: bool}` →
  `{"created": [{"key", "url"?, "title", "edges"}], "errors": [{"title","error"}], "missing": [EdgeRef]}`.
  One ticket for all edges, or one per edge with `split` (at most 50). `502` when nothing could be created.
- `GET /tickets` (viewer) → the last 500 tickets created, newest first:
  `[{"at","by","target","target_name","key","url"?,"title","edges": ["SRC -[Kind]-> DST"]}]`.

### Posture

- `GET /posture` → `[Snapshot]` oldest first, where
  `Snapshot = {"snapshot_id","created_at","nodes","edges","tier0","exposed_principals","total_principals","exposure_percent","findings":{"critical":n,"high":n,"medium":n,"low":n}, "finding_counts": {"<finding id>": n}}`
- `GET /posture/diff?from=<snapshot_id>&to=<snapshot_id>` →
  `{"from","to","findings":[{"id","title","severity","added": n,"removed": n,"added_items":[ItemLabel],"removed_items":[ItemLabel]}]}`
  where `ItemLabel = {"key": "...", "label": "ALICE@CORP -[AdminTo]-> WS1.CORP"}` (up to 200 per side). Only
  findings with changes are listed.
- `DELETE /posture/{snapshot_id}` (admin) removes a history entry.

### Data quality

`GET /quality` → `{"domains": [...], "tenants": [...]}` — per AD domain: users, enabled computers,
`session_coverage` (% of enabled computers with `HasSession`), `local_group_coverage` (% with inbound
`AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM`), `acl_coverage` (% of objects whose security
descriptor was read; `null` when the collector does not say); per Entra tenant: object counts,
`role_assignments`, `memberships`, `app_owner_coverage`, `device_owner_coverage`, `subscriptions`. Both carry
`collected_at` (newest source naming the domain / tenant; `collected_at_exact: false` when only the file date
is known), `age_days`, `sources` and plain-language `warnings` (coverage below 10 % for sessions / local
groups, below 90 % for ACLs, missing role assignments, memberships, owners or subscriptions, data older than
30 days). Also available on the command line: `copperhound quality <graph>`.

---

## 5. Reports, notifications, schedules and alerts

Notification, schedule and alert-rule configuration is **admin-only** (it holds outbound targets and
secrets); the alert history is readable by **analysts**. Changes are [audited](#audit-log-admin) (e.g.
`"PUT /notify/channels"`). Stored in `<data>/notify.json`, `<data>/schedules.json`, `<data>/alert_rules.json`.

### Reports

`GET /report?format=html|md|csv&title=&plan_steps=10&items=25&download=1[&env=<id>]` — a self-contained
assessment report for the current snapshot: posture grade, exposure, findings with measured impact, posture
trend, remediation plan, choke points and per-finding details. HTML has inline CSS/SVG and print styles
(print → PDF); CSV has one row per finding item. `202` while analysis is computing. See also
[Risk acceptance](#risk-acceptance) and [`env`](#environments-scope-by-domain--tenant).

CLI: `copperhound report <graph> -o report.html|.md|.csv`.

### Notification channels (admin)

`GET /notify/channels` → `{"channels":[ChannelOut]}`

```jsonc
// ChannelOut — secrets are never returned
{"id":"c-1a2b3c4d5e6f","name":"SOC hook","type":"webhook","enabled":true,
 "url_set":true,"url_hint":"https://hooks.example.com/…","secret_set":true}            // webhook
{"id":"…","name":"…","type":"slack","enabled":true,"url_set":true,"url_hint":"https://hooks.slack.com/…"}
{"id":"…","name":"…","type":"teams","enabled":true,"url_set":true,"url_hint":"https://…/…",
 "teams_format":"adaptive"}                                                              // or "messagecard"
{"id":"…","name":"…","type":"email","enabled":true,"smtp_host":"smtp.example.com","smtp_port":587,
 "smtp_security":"starttls","smtp_username":"pd","smtp_password_set":true,
 "email_from":"CopperHound <pd@example.com>","email_to":["soc@example.com"]}
```

`PUT /notify/channels` `{"channels":[ChannelIn]}` replaces the **whole list** and returns the same shape as
`GET`.

```jsonc
// ChannelIn
{"id"?: "c-…",               // omit for a new channel (server assigns c-<12 hex>)
 "name": "1-100 chars", "type": "webhook|slack|teams|email", "enabled"?: true,
 "url"?: "https://…",        // webhook/slack/teams: required on create; http(s) only
 "secret"?: "…",             // webhook only: HMAC-SHA256 key
 "teams_format"?: "adaptive|messagecard",
 "smtp_host"?: "…", "smtp_port"?: 587, "smtp_security"?: "starttls|tls|none",
 "smtp_username"?: "…", "smtp_password"?: "…", "email_from"?: "…", "email_to"?: ["…"]}
```

- **Secret fields** (`url`, `secret`, `smtp_password`): absent or `null` keeps the stored value of the
  channel with the same `id` and `type`; `""` clears it; a string replaces it. The UI can send back what
  `GET` returned plus only the fields the user typed.
- Validation (`400 {"error"}`): name 1-100 chars, ≤ 50 channels, unique ids, URL scheme `http`/`https` with
  a host, `smtp_host` a bare host name, `email_from` and 1-50 `email_to` valid addresses, credentials
  refused with `smtp_security:"none"`. `smtp_port` defaults to 587 (`starttls`), 465 (`tls`, implicit TLS)
  or 25 (`none`).
- Removing a channel that a schedule or the alert rules still reference is allowed; those deliveries then
  report `"error":"unknown channel"`.
- `POST /notify/channels/{id}/test` sends a test message (also when the channel is disabled) and returns
  **Delivery**: `{"channel":"c-…","name":"…","ok":true,"attempts":1,"error"?: "HTTP 404: …"}` — `200` even
  when delivery failed (check `ok`); `404` for an unknown id. Can take up to ~1 min when the target is
  unreachable (retries).

**Delivery behaviour.** HTTP: 10 s connect / 15 s total timeout, redirects **not** followed. SMTP: 30 s. Up
to 3 attempts (backoff 2 s, 6 s) on network errors, timeouts, HTTP 429 / 5xx and transient SMTP errors;
other 4xx fail immediately. TLS is rustls (no OpenSSL); `starttls` requires the upgrade. Disabled channels
are skipped by schedules and alerts (`"error":"channel disabled"`).

**Payloads.**
- *Generic webhook*: `POST` JSON
  `{"source":"copperhound","event":"report|alert|test","sent_at":"RFC3339","title","text","facts":[{"name","value"}],"link":"…|null","data":{…}}`
  with headers `X-CopperHound-Event: <event>` and, when a secret is set,
  `X-CopperHound-Signature: sha256=<hex HMAC-SHA256(secret, raw request body)>`. Verify against the raw
  bytes, not re-serialised JSON.
- *Slack*: `{"text":"*title*\n…","unfurl_links":false}` (mrkdwn).
- *Teams*: `adaptive` — `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":<AdaptiveCard 1.4>}]}`
  (Workflows / Power Automate webhooks); `messagecard` — legacy Office 365 connector `MessageCard`.
- *Email*: plain-text body; scheduled reports attach the rendered report
  (`copperhound-report-<snapshot>.<html|md|csv>`).
- `link` is `COPPERHOUND_PUBLIC_URL` (e.g. `https://copperhound.corp.example`) when set, otherwise `null`.

**SSRF note.** The server makes outbound requests to admin-configured URLs and SMTP hosts. Internal
addresses are deliberately allowed (on-prem chat / SIEM relays); restrict egress at the network level if
admins should not reach internal services through CopperHound.

### Scheduled reports (admin)

```jsonc
// Schedule
{"id":"s-…","name":"Weekly posture","enabled":true,
 "when": {"kind":"daily","at":"07:30"}                    // HH:MM (two digits each), UTC
       | {"kind":"weekly","weekday":"mon","at":"07:30"}   // mon…sun (full names accepted on input, stored as 3 letters)
       | {"kind":"interval","hours":6},                   // 1-744, counted from the previous run
 "format":"html|md|csv",          // email attachment format
 "title":"",                      // report / message title ("" → name)
 "plan_steps":10,                 // 0-50 remediation-plan steps in the attached report
 "channels":["c-…"],
 "created_at":"RFC3339","next_run":"RFC3339|null","running":false,
 "last_run":"RFC3339|null","last_status":"ok|partial|failed|skipped|null","last_error":"…|null",
 "last_deliveries":[Delivery]}
```

- `GET /schedules` → `{"schedules":[Schedule],"public_url":"…|null"}`
- `POST /schedules` `{"name","when","format"?:"html","title"?:"","plan_steps"?:10,"channels":["c-…"],"enabled"?:true}` → `Schedule`
- `PUT /schedules/{id}` same body (full replacement of the definition; run history kept; `next_run` recomputed) → `Schedule`
- `DELETE /schedules/{id}` → `{}`
- `POST /schedules/{id}/run` → `202 {"started":true}`; `409` if already running; `404` unknown id. The run
  happens in the background — poll `GET /schedules` for `running` / `last_status`. A manual run does not
  move `next_run` (except for `interval` schedules, which count from the last run).
- Validation (`400`): name 1-100 chars, valid `when`, `format`, title ≤ 200 chars, `plan_steps` ≤ 50, 1-20
  existing channel ids, ≤ 100 schedules.
- A background task checks for due schedules every 20 s; a run missed while the server was down happens once
  at the next check. `skipped` = no finished analysis (no graph yet, or analysis still computing).
  `partial` = some channels failed.
- Message: grade, exposure % (exposed / total principals), counts by severity, top 5 findings and the delta
  vs. the previous posture snapshot. Webhook `data`:
  `{"snapshot_id","grade","exposure_percent","exposed_principals","total_principals","findings":{"critical","high","medium","low"},"top_findings":[{"id","title","severity","count"}],"delta":{"previous_snapshot_id","previous_grade","previous_exposure_percent","exposure_points","new_findings":[id],"resolved_findings":[id],"item_change"}|null}`
- The report itself (with the remediation plan) is rendered only when one of the channels is email.

### Change alerts

After every ingest that produces a new posture snapshot (manual, watch folder, API), the posture is
compared with the previous one (`<data>/alert_state.json` keeps the exposed-principal set as 64-bit hashes
and the top choke points). Evaluation and delivery run in the background and never block ingest.

`GET /alerts/rules` (admin) → `AlertRules`; `PUT /alerts/rules` (admin) with the full object (missing fields
take the defaults) → `AlertRules`.

```jsonc
// AlertRules (defaults shown)
{"enabled":false,
 "channels":[],                                 // existing channel ids (≤ 20); ≥ 1 when enabled
 "grade_worse":true,                            // grade letter got worse (A→B…)
 "exposure_increase_points":5.0,                // exposure % rose by ≥ X points; null = off (0-100)
 "new_finding_severities":["critical","high"],  // finding types with 0 items before and > 0 now; [] = off
 "new_tier0_principals_min":10,                 // ≥ N principals newly have a path to Tier Zero; null = off (≥ 1)
 "choke_points_changed":false,                  // the top-N choke-point edge set changed
 "choke_points_top":10,                         // N, 1-100
 "watch":[]}                                    // object ids or names (≤ 500): alert when one newly has a path to Tier Zero
```

The first ingest never alerts. The exposed-set and choke-point rules need state saved by a previous ingest
(they start working from the second ingest that saves it); grade, exposure and findings fall back to the
previous posture snapshot. Accepted findings never trigger new-finding alerts.

`GET /alerts?limit=100` (analyst; max 500) → `{"alerts":[Alert]}` newest first. Stored in
`<data>/alerts.jsonl` (rotates to `alerts.1.jsonl` at 8 MB).

```jsonc
// Alert
{"id":"a-…","ts":"RFC3339","snapshot_id":"g-…","previous_snapshot_id":"g-…",
 "grade_before":"B","grade_after":"D","exposure_before":3.0,"exposure_after":9.5,
 "triggers":[{"rule":"grade_worse|exposure_increase|new_findings|new_tier0_principals|choke_points_changed|watched_gained_path","message":"…"}],
 "new_findings":[{"id","title","severity","count"}],
 "new_tier0_principals":3,"new_tier0_sample":["ALICE@CORP.LOCAL"],      // ≤ 10 names
 "choke_points_added":["A -[GenericAll]-> B"],"choke_points_removed":[], // ≤ 10 each
 "new_paths":[{"objectid","name","kind","watched":true,                 // watched first, then the sample
               "hops":[{"src","src_name","kind","dst","dst_name"}]}],   // a shortest path into Tier Zero at that snapshot
 "deliveries":[Delivery]}
```

**Watched principals.** `watch` fires `watched_gained_path` for a listed user, computer, service principal or
group that has an attack path to Tier Zero now and had none at the previous ingest. Groups count too (a group
"has a path" when the group itself does). An object added to the list since the last ingest fires only if it
is a principal known to have been unexposed then; otherwise it is recorded and can fire from the next ingest
on. Every alert with `watched_gained_path` or `new_tier0_principals` carries `new_paths`: one shortest path
per principal, which the Alerts page draws on the canvas.

Alerts are recorded only when at least one rule fired and `enabled` is true. Alert webhooks use
`event:"alert"` with the `Alert` object as `data`.

---

## 6. Administration

### Own account and API tokens

- `GET /me` → `{"username","role","created_at","last_login","disabled","source","mfa","via_token","tokens":[Token],"permissions":{"analyse","upload","modify","admin"}}`
- `PUT /me/password` `{"current_password","new_password"}` (≥ 12 chars; signs out the user's other sessions;
  not allowed with an API token → `403`; SSO accounts → `400`) → `{"changed": true, "note"}`
- `GET /me/tokens` → `{"tokens":[Token]}`
- `POST /me/tokens` `{"name","expires_days"?}` (`expires_days` 1-3650; omit for no expiry) → `Token` plus
  `"token":"cht_…"` (**shown once**; only a SHA-256 hash is stored) and `"bloodhound_key"` (for
  [`bhesignature`](#8-bloodhound-compatible-api-apiv2) signing)
- `DELETE /me/tokens/{id}` → `{"deleted": "<id>"}`

`Token = {"id","name","prefix","created_at","expires_at","last_used"}`. For using tokens see
[Authentication](#authentication).

### Two-factor sign-in (TOTP)

Local accounts can protect password sign-in with a TOTP authenticator (RFC 6238: SHA-1, 30 s, 6 digits, ±1
step, each code accepted once) and 10 one-time recovery codes. API tokens and SSO accounts are not affected.
Changes need an interactive session (not an API token; otherwise `403`).

- `GET /me/mfa` → `{"enabled", "pending", "recovery_codes_left"}`
- `POST /me/mfa/setup` → `{"secret", "uri": "otpauth://…", "qr_svg"}` (new pending secret; refused while on)
- `POST /me/mfa/enable` `{"code"}` → `{"enabled": true, "recovery_codes": [...], "note"}` (shown once; stored hashed)
- `POST /me/mfa/disable` `{"code"}` (current code or a recovery code) → `{"enabled": false}`
- `DELETE /users/{name}/mfa` (admin) — reset for a lost device; ends the user's sessions →
  `{"username", "mfa": false}`

At sign-in, send the code as `otp` to `POST /login` (see [Authentication](#authentication)).
`GET /users` shows `"mfa": true` per account.

### Users (admin)

- `GET /users` → `{"users":[User],"roles":[{"id","description"}]}` where
  `User = {"username","role","created_at","disabled","last_login","tokens":[Token],"source":"local"|"oidc","mfa"}` (SAML accounts also report `"oidc"`)
- `POST /users` `{"username","password","role"}`
- `PUT /users/{name}` `{"role"?,"password"?,"disabled"?}`
- `DELETE /users/{name}` → `{"deleted": "<name>"}`
- `DELETE /users/{name}/tokens/{id}` revokes another user's token → `{"deleted": "<id>"}`
- The last enabled admin cannot be demoted, disabled or deleted (`400`). Disabling or resetting a password
  ends that user's sessions. SSO accounts have no password (`password` → `400`; see
  [SSO accounts](#sso-accounts)).
- Stored in `<data>/users.json` (Argon2id hashes).

### Audit log (admin)

- `GET /audit?limit=200&user=&action=` → `{"entries":[{"ts","user","role","action","method","path","status","ip","detail"}]}` newest first.
- Records every non-`GET` request (`action` = `"POST /zones"`, `"PUT /users/{name}"`, …), `login`,
  `login-failed`, `login-locked`, `denied`, `database-cleared`, and the SSO actions `sso-login`,
  `sso-login-failed`, `sso-config-changed` (see [SSO audit actions](#sso-audit-actions)). Stored in
  `<data>/audit.jsonl` (rotates at 64 MB).

### Settings and watch folder (admin)

- `GET /settings` → `{"settings":{"watch":{"enabled","dir","mode","settle_seconds","archive","keep_archives"},"analysis":{"unified_tier0":true},"ingest":{"merge_policy":"newest","session_window_hours":0}},"watch_dir_resolved","watch_status":{"last_scan","last_import","last_job","imported_files","pending":[],"last_error"}}`
- `PUT /settings` with the `settings` object. Omitted fields take their defaults.
- `analysis.unified_tier0` (default `true`): AD and Entra ID Tier Zero form one target set and `/tier0` and
  `/path` follow edges across the hybrid boundary (`SyncedTo*`, `SeamlessSSO`, `EntraConnectCredentials`).
  `false` keeps each realm separate. Changing it drops the cached `/tier0` report.
- `ingest`: see [Collection-aware merging](#collection-aware-merging-and-sources).
- **Watch folder.** When enabled, the server polls the folder (default `<data>/watch`; see
  [`COPPERHOUND_WATCH_DIR`](#9-environment-variables)) every 10 s. A collector file (any upload extension) is imported once its size and
  mtime are unchanged for `settle_seconds` and every file in the drop has settled. Files are **moved** into
  uploads and an ingest job starts (`trigger: "watch"`). `replace` mode archives the previous uploads to
  `<data>/archive/` (last `keep_archives` kept; deleted if `archive` is false); `merge` adds to them.

SSO settings live under `/settings/sso` and `/settings/saml` (see [Single sign-on](#7-single-sign-on)).

### Built-in LDAP collector (admin)

The server reads domain controllers itself (no SharpHound run):

- `GET /collect/ldap` → targets (`password` never returned; `password_set`, `running`, `last_run`,
  `last_ok`, `last_error`, `last_objects`, `last_seconds`).
- `PUT /collect/ldap` `{"id"?, "name", "enabled", "url": "ldaps://dc01.corp.local", "starttls"?, "allow_plain"?, "insecure_skip_verify"?, "bind_dn", "password"?, "base_dn"?, "include_configuration"?: true, "interval_hours"?: 24}`
  — create or update (omit `password` to keep it). Plain `ldap://` needs `starttls` or an explicit
  `allow_plain`.
- `POST /collect/ldap/{id}/test` → `{"ok", "dns_host_name", "default_naming_context"}` or `{"ok": false, "error"}`.
- `POST /collect/ldap/{id}/run` → `{"started": "<id>"}`.
- `DELETE /collect/ldap/{id}` → `{"deleted": "<id>"}`.

A run binds (simple bind over TLS), reads the RootDSE, pages through the domain and configuration partitions
with the SD flags control (owner + DACL, readable without admin rights), completes `member` beyond 1,500
values by range retrieval, reads the LAPS schema GUIDs, writes `uploads/ldap-<name>.ldif.gz` (replaced each
run) and queues an ingest. Enabled targets run every `interval_hours` (0 = manual). Sessions and local groups
are not in LDAP. The bind password is stored in `<data>/ldap_collect.json`.

### Collector clients (admin)

- `POST /collectors` `{"name", "kind": "sharphound|azurehound|bloodhound-python|ldap", "interval_hours"?: 24}`
  → `{"collector": Collector, "token": "cht_…" (shown once), "token_id", "bloodhound_key", "note", "commands": {"script_name", "script", "schedule"}}`.
  Creates the upload-only account `collector-<name>` with an API token; the commands collect, upload with
  that token and start an ingest.
- `GET /collectors` → `[Collector]` with `status`: `ok`, `stale` (no upload within twice `interval_hours`) or
  `never`, plus `last_upload_at`, `last_files`, `uploads`.
- `DELETE /collectors/{id}` deletes the client and its account and token → `{"deleted": "<id>", "account_removed": "collector-<name>"}`.

Each upload by a collector account counts as its check-in. Stored in `<data>/collectors.json`.

### Node kind styles

`GET /kind-styles` (viewer) → `{"<kind>": {"color"?: "#rrggbb", "icon"?: "🐙", "icon_name"?}}`;
`PUT /kind-styles` (admin) with the full map. Shared defaults for every user (a user's own colours in the web
settings still win).

BloodHound's `POST /api/v2/custom-nodes` (admin)
`{"custom_types": {"Kind": {"icon": {"type", "name", "color"}}}}` merges colours (Font Awesome names are kept
as `icon_name`, not drawn).

### Network conduits

Firewall conduits between network zones, so paths and exposure can respect them (details:
[OT.md](OT.md#network-reachability)). Hosts are placed in zones by their `net_zone` property.

`GET /network` (viewer) → `{"conduits": Conduits | null, "zones": [{"name", "hosts"}], "error": null}`;
`zones` and `error` are resolved against the loaded graph. `PUT /network` (admin) with Conduits replaces the
configuration (400 on unknown services or invalid names); `DELETE /network` (admin) removes it.

```json
{"attacker_zone": "IT",
 "conduits": [{"from": "IT", "to": "OT-DMZ", "services": ["rdp"], "note": "jump host"},
              {"from": "OT-L2", "to": "OT-L1", "services": ["plc"]}]}
```

Services: `smb`, `rdp`, `winrm`, `rpc`, `mssql`, `plc`, `ssh`, `*`; `"*"` as `from` or `to` is every zone.

`GET /network/exposure?zone=tier0` (viewer) → `{"zone", "identity_exposed", "network_exposed",
"total_principals", "elapsed_ms"}`: principals with any attack path to the zone, and those with a path the
conduits allow.

### Backup and restore (admin)

- `GET /backup[?uploads=1&tls=1]` → zip (`manifest.json` + files): `users.json`, `sso.json`, `saml.json`,
  `settings.json`, `notify.json`, `alert_rules.json`, `schedules.json`, `zones.json`, `saved_queries.json`,
  `marks.json`, `accepted_risks.json`, `collectors.json`, `posture.json`, `snapshots/*`, `alert_state.json`,
  `audit.jsonl`, `alerts.jsonl`; with `uploads=1` the collector uploads, with `tls=1` `tls/cert.pem` /
  `tls/key.pem`. Graphs are not included (rebuilt from the uploads). The archive holds password, token and
  SSO secrets: treat it as a credential.
- `POST /restore` (multipart field `backup`) →
  `{"staged_files", "includes_uploads", "backup_created_at", "restart_required": true}`. Only allow-listed
  names are accepted (anything else, e.g. `../x`, rejects the whole archive). The files are staged in
  `<data>/restore-pending/` and applied at the next start before any state is loaded; uploads in the backup
  replace the current ones and a rebuild is queued.

### Database management (admin)

`POST /database/clear` permanently deletes stored data; `"confirm": "DELETE"` is required and `409` is
returned while an ingest job runs:

```jsonc
{"confirm": "DELETE",
 "uploads": "all",            // or ["a.zip", …]; omit to keep uploads
 "rebuild": true,             // then ingest what is left (nothing left: unload the graph)
 "graph": false,              // unload the graph and delete stored snapshots
 "marks": false, "zones": false, "saved_queries": false, "posture_history": false}
```

→ `{"uploads_removed": [...], "graph_snapshots_removed": n, "marks_cleared": true, …, "job_id": "j-…"}` (only
the parts that ran). Users, SSO / notification settings and the audit log are never touched; the action is
audited as `database-cleared`. The web UI offers it under Data → Database management.

---

## 7. Single sign-on

CopperHound supports OpenID Connect and SAML 2.0. Both end in an ordinary session token, used exactly like
one from `/login`. The `/auth/…` endpoints are public.

### Sign-in providers

**`GET /auth/providers`** — what the sign-in page should offer:

```json
{
  "password_login": true,
  "admin_password_login": true,
  "sso": { "enabled": true, "type": "oidc", "display_name": "Corp SSO", "login_url": "/api/v1/auth/oidc/login" },
  "saml": { "enabled": false, "display_name": "Corp SSO", "login_url": "/api/v1/auth/saml/login" }
}
```

- `sso.enabled` — show the SSO button (label `display_name`); it is a plain link / full-page navigation to
  `login_url`, never an XHR. `saml` is the same for SAML.
- `password_login` — show the username/password form for everyone.
- `admin_password_login` — when `password_login` is `false` but this is `true`, keep a discreet
  "administrator sign-in" link to the password form (break-glass for the built-in `admin`). `POST /login`
  for an account that policy refuses returns
  `403 {"error":"password sign-in is disabled for this account; use single sign-on"}` (only after a correct
  password, so it does not reveal accounts).

### OpenID Connect

Authorization-code flow with PKCE (S256), `state` and `nonce`; works with Entra ID, Okta, Keycloak, Google
and any OIDC provider with discovery.

**`GET /auth/oidc/login?return_to=/#/findings`** — browser navigation. Redirects (`303`) to the IdP's
authorization endpoint and sets an HttpOnly, `SameSite=Lax` cookie `ch_oidc` (path `/api/v1/auth/oidc`,
10 min) binding the attempt to this browser. `return_to` is optional and only accepted as a same-origin
relative path (starts with `/`, not `//` or `/\`, no whitespace/control characters, ≤ 512 chars); anything
else is replaced by `/`.

**`GET /auth/oidc/callback`** — the redirect URI registered at the IdP. Always answers with a `303` back into
the SPA:

- success → `/#/sso?code=<64 hex chars>`
- failure → `/#/login?sso_error=<code>`

| `sso_error` | Meaning (details are in the audit log, never in the URL) |
|---|---|
| `disabled` | SSO is not enabled / not configured |
| `config` | redirect URI could not be derived (set `redirect_url`) |
| `idp_unreachable` | discovery document could not be fetched or is invalid |
| `state` | unknown/expired/re-used `state`, or the `ch_oidc` cookie is missing (sign-in started in another browser or took > 10 min) — just retry |
| `idp_error` | the IdP returned an error (e.g. user cancelled, consent denied) |
| `token` | code redemption failed or the ID token was rejected (signature, issuer, audience, expiry, nonce) |
| `denied` | the user is in no mapped group and `default_role` is `deny`, or the email domain is not allowed |
| `disabled_user` | the CopperHound account is disabled |
| `conflict` | the username already belongs to a local account or another IdP identity |
| `server` | could not store the account |

**`POST /auth/oidc/exchange`** `{"code":"<code from /#/sso>"}` →
`{"token":"…","username":"alice@corp.example","role":"analyst","return_to":"/#/findings"}`. The code is
single-use and valid for 60 s; otherwise `401 {"error":"invalid or expired sign-in code"}` (`403` if the
account was disabled in between). The SPA should call this immediately on `#/sso`, store the token like a
password-login token, remove the code from the URL (`history.replaceState`) and navigate to `return_to`.

### SSO accounts

- Created just-in-time on first SSO sign-in; `User` objects (`/users`, `/me`) carry
  `"source": "local" | "oidc"`. SSO accounts have no password: `POST /login` fails, `PUT /users/{name}` with
  `password` and `PUT /me/password` return `400`.
- Bound to the IdP's `(issuer, sub)`, not the username. The username comes from `username_claim` (default
  `preferred_username`), falling back to `email`, then `sub` (characters outside `A-Z a-z 0-9 . _ - @`
  become `_`). It is fixed at creation; a new identity whose username is already taken (by any local
  account, including `admin`, or another identity) is refused with `conflict`.
- The role is re-evaluated on every SSO sign-in (the IdP is authoritative; a manual role change lasts until
  the next sign-in). A sign-in that maps to no role ends the account's existing sessions. Disabled accounts
  are refused. SSO users may create personal API tokens; disable the account to revoke access fully.
- SAML accounts are SSO accounts linked to `saml:<IdP entity id>` + NameID.

### OIDC configuration (admin)

**`GET /settings/sso`** →

```json
{
  "config": {
    "enabled": true,
    "display_name": "Corp SSO",
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "client_id": "…",
    "client_secret_set": true,
    "redirect_url": "",
    "scopes": ["openid", "profile", "email"],
    "username_claim": "preferred_username",
    "groups_claim": "groups",
    "role_mapping": { "admin": ["<group id or role>"], "analyst": [], "viewer": [] },
    "default_role": "deny",
    "allowed_email_domains": [],
    "allow_password_login": true,
    "disable_admin_password_login": false,
    "allow_insecure_http": false
  },
  "env_overrides": ["client_secret"],
  "redirect_url_effective": "https://copperhound.corp.example/api/v1/auth/oidc/callback",
  "callback_path": "/api/v1/auth/oidc/callback",
  "sso_admin_signed_in": false,
  "admin_password_login": true,
  "break_glass_env": false
}
```

`config` is the effective configuration (file + environment); the client secret is never returned. Fields
in `env_overrides` are set by [environment variables](#9-environment-variables), win over the stored value
and should be shown read-only. `redirect_url_effective` is the URL sent to the IdP for a browser reaching the
server the way this request did; register exactly this URL at the IdP.

**`PUT /settings/sso`** with the `config` object (unknown keys such as `client_secret_set` are ignored;
omitted keys take their defaults). `client_secret`: omitted or `null` keeps the stored secret, `""` clears
it, a string replaces it. Returns the same shape as `GET`. `400` with a message on validation errors:

| Field | Rules / default |
|---|---|
| `enabled` | default `false` |
| `display_name` | ≤ 64 chars, default `"Single sign-on"` |
| `issuer` | required when enabled; `https://` (plain `http://` only for loopback or with `allow_insecure_http`). Must equal the `issuer` of `<issuer>/.well-known/openid-configuration` (trailing `/` ignored) |
| `client_id` | required when enabled |
| `client_secret` | optional (public client + PKCE if empty); sent as `client_secret_basic` unless the IdP only supports `client_secret_post` |
| `redirect_url` | empty = derived: `COPPERHOUND_PUBLIC_URL` + callback path, else the request origin (`X-Forwarded-Proto` / `X-Forwarded-Host` honoured). If set, must end with `/api/v1/auth/oidc/callback` (a path prefix in front is allowed for reverse proxies) |
| `scopes` | default `["openid","profile","email"]`; `openid` is always added |
| `username_claim` | default `preferred_username` |
| `groups_claim` | default `groups`; comma-separated list of claims, dotted paths allowed — `groups,roles` (Entra groups + app roles), `realm_access.roles` (Keycloak) |
| `role_mapping` | `{admin:[], analyst:[], viewer:[]}` — claim values (case-insensitive exact match); highest matching role wins |
| `default_role` | `viewer`, `analyst` or `deny` (default). `admin` is not allowed |
| `allowed_email_domains` | optional; if non-empty the `email` claim must be in one of them and `email_verified` must not be `false` |
| `allow_password_login` | default `true`. `false`: local accounts other than the built-in `admin` cannot use passwords while SSO is enabled (their API tokens keep working) |
| `disable_admin_password_login` | default `false`. Only accepted with `enabled: true`, `allow_password_login: false` **and** after an enabled SSO account with the admin role has completed a sign-in (`sso_admin_signed_in`) |
| `allow_insecure_http` | default `false` |

Every change is audited as `sso-config-changed` (`detail: "changed: issuer, client_secret"`; values are never
logged).

**`POST /settings/sso/test`** `{}` (tests the effective config) or
`{"issuer":"https://…","allow_insecure_http":false}` (tests a candidate before saving) → always `200`:

```json
{ "ok": true, "issuer": "…", "authorization_endpoint": "…", "token_endpoint": "…", "jwks_uri": "…",
  "userinfo_endpoint": "…", "end_session_endpoint": "…", "scopes_supported": ["openid", "…"],
  "jwks_keys": 2, "warnings": [] }
```
or `{"ok": false, "error": "discovery document issuer \"…\" does not match the configured issuer \"…\""}`.

Outbound OIDC requests (10 s timeout, no redirects, 1 MiB response cap) use rustls with the built-in Mozilla
root set plus the system store if present, and honour `HTTPS_PROXY` / `NO_PROXY`. Use
`COPPERHOUND_OIDC_CA_FILE` for an internal IdP's CA.

### SAML 2.0

Public:

- `GET /auth/saml/login?return_to=/…` → `303` to the IdP (HTTP-Redirect AuthnRequest) and a `ch_saml`
  cookie (`HttpOnly; SameSite=None; Secure`) binding the request to the browser.
- `POST /auth/saml/acs` (form: `SAMLResponse`, `RelayState`) → `303` to `/#/sso?code=…` (redeem at
  `POST /auth/oidc/exchange`, as for OIDC) or `/#/login?sso_error=<code>` (`state`, `token`, `denied`,
  `disabled`, `config`, `conflict`, `disabled_user`; meanings as in the [OIDC table](#openid-connect)).
- `GET /auth/saml/metadata` → SP metadata XML (entity ID, ACS URL).
- `GET /auth/providers` returns `saml` (see [Sign-in providers](#sign-in-providers)).

Admin: `GET /settings/saml` →
`{"config": SamlConfig, "sp_entity_id_effective", "acs_url_effective", "metadata_url", "idp": {"entity_id", "sso_url", "certificates": [sha256 fingerprints]} | null}`;
`PUT /settings/saml` with a full `SamlConfig`:

```json
{"enabled": true, "display_name": "Corp SSO", "idp_metadata": "<md:EntityDescriptor …>",
 "sp_entity_id": "", "acs_url": "",
 "username_attribute": "", "groups_attribute": "groups", "email_attribute": "email",
 "role_mapping": {"admin": ["CH-Admins"], "analyst": [], "viewer": []},
 "default_role": "deny", "allowed_email_domains": []}
```

Empty `sp_entity_id` / `acs_url` derive from `COPPERHOUND_PUBLIC_URL` or the request origin; empty
`username_attribute` uses the NameID. Accounts are linked as described in [SSO accounts](#sso-accounts).
The password sign-in rules of `/settings/sso` apply while either OIDC or SAML is enabled. Stored in
`<data>/saml.json`.

### Break-glass: when may the built-in `admin` use its password?

Always, unless **all** of these hold: SSO is enabled and configured, `allow_password_login` is `false`,
`disable_admin_password_login` is `true`, an enabled SSO account with the admin role has signed in at least
once, and `COPPERHOUND_SSO_BREAK_GLASS` is not set. The condition is re-checked on every password attempt, so
disabling or demoting the last SSO admin, or disabling SSO, restores the admin password. If the
IdP itself is unavailable, set `COPPERHOUND_SSO_BREAK_GLASS=1` and restart (or edit/remove
`<data>/sso.json`). `COPPERHOUND_ADMIN_PASSWORD` still resets the admin password at start-up.

### SSO audit actions

`sso-login` (user, role, `detail: "sub=…; groups=N"`), `sso-login-failed`
(`detail: "<sso_error code>: <reason>"`, e.g. `token: ID token nonce does not match …`,
`denied: not in any mapped group …`), `sso-config-changed`; password attempts refused by policy are
`login-failed` with status `403`.

---

## 8. BloodHound-compatible API (`/api/v2`)

A subset of BloodHound CE's API, so existing upload tooling works unchanged:

- `POST /api/v2/login` `{"login_method":"secret","username","secret"}` →
  `{"data":{"session_token","user_id","auth_expired":false}}` (accounts with two-factor sign-in must use a
  token).
- `POST /api/v2/file-upload/start` → `{"data":{"id",…}}`; `POST /api/v2/file-upload/{id}` with a JSON
  (`application/json`) or zip (`application/zip`) body, one file per call; `POST /api/v2/file-upload/{id}/end`
  starts an ingest of all uploads (`"ingest_job"`); `GET /api/v2/file-upload` lists your upload jobs.
  Upload-only accounts may use all of these (see [Roles](#roles)).
- `POST /api/v2/custom-nodes` (admin) merges kind colours; see [Node kind styles](#node-kind-styles).
- Authentication: `Authorization: Bearer <session or cht_ token>`, or BloodHound request signing —
  `Authorization: bhesignature <token id>`, `RequestDate` (RFC 3339, within an hour), `Signature` =
  base64(HMAC-SHA256 chain over `METHOD+URI`, the first 13 characters of `RequestDate`, then the body), keyed
  by the token's **BloodHound-compatible key** (`bloodhound_key`, shown with the token when it is created;
  also returned for collectors). As in BloodHound, a signature covers only the hour of the date, so identical
  requests within the hour are accepted; use [`CH-HMAC`](#signed-requests-ch-hmac) for replay-proof signing.

---

## 9. Environment variables

| Variable | Purpose |
|---|---|
| `COPPERHOUND_LISTEN` | address to listen on (`copperhound serve --listen`, default `127.0.0.1:8080`) |
| `COPPERHOUND_DATA_DIR` | data directory (`--data-dir`, default `data`) — the `<data>` in this document |
| `COPPERHOUND_WEB_DIR` | built web UI directory (`--web-dir`, default `web/dist`); without it only the API is served |
| `COPPERHOUND_TLS` | `self-signed` (certificate generated in `<data>/tls/`) or `off` (default) |
| `COPPERHOUND_TLS_CERT`, `COPPERHOUND_TLS_KEY` | PEM certificate and key (set both) |
| `COPPERHOUND_TLS_HOSTNAMES` | comma-separated host names for the self-signed certificate |
| `COPPERHOUND_ADMIN_PASSWORD` | password of the built-in `admin` (authoritative when set; else generated at first start and stored in the data directory) |
| `COPPERHOUND_WATCH_DIR` | enables the [watch folder](#settings-and-watch-folder-admin) on first start, at this path |
| `COPPERHOUND_MAX_SIGNED_BODY_MB` | largest body of a `bhesignature`-signed request, read before its signature can be checked (default 4096) |
| `COPPERHOUND_PUBLIC_URL` | external base URL, e.g. `https://copperhound.corp.example`: `link` in notifications, derived OIDC redirect URL and SAML SP entity ID / ACS URL |
| `COPPERHOUND_OIDC_*` | OIDC configuration overrides (below) |
| `COPPERHOUND_OIDC_CA_FILE` | PEM bundle of extra trusted CAs for an internal IdP |
| `COPPERHOUND_SSO_BREAK_GLASS` | `1` re-enables the built-in admin's password sign-in (see [Break-glass](#break-glass-when-may-the-built-in-admin-use-its-password)) |
| `HTTPS_PROXY` / `NO_PROXY` | honoured by outbound OIDC requests |

**OIDC variables.** `COPPERHOUND_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URL`, `_SCOPES`
(space/comma separated), `_USERNAME_CLAIM`, `_GROUPS_CLAIM`, `_ADMIN_GROUPS`, `_ANALYST_GROUPS`,
`_VIEWER_GROUPS`, `_ALLOWED_EMAIL_DOMAINS` (comma separated), `_DEFAULT_ROLE`, `_DISPLAY_NAME`,
`_ALLOW_PASSWORD_LOGIN`, `_ALLOW_INSECURE_HTTP`, `_ENABLED` (setting `_ISSUER` implies `_ENABLED=true`). They
override the matching fields of `<data>/sso.json` (read at start-up) and are listed in `env_overrides` by
`GET /settings/sso`.
