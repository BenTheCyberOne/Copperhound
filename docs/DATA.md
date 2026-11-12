# Data sources and merging

What CopperHound ingests, how to collect raw LDAP data, which edges it derives,
and how several collections are merged into one graph.

## Supported input

| collector | format | notes |
|---|---|---|
| SharpHound (v4–v6 JSON, CE) | `{"data":[…],"meta":{…}}`, `.zip` | `meta` before or after `data` |
| bloodhound-python | same as SharpHound | |
| ldapdomaindump | `domain_users.json`, `domain_groups.json`, `domain_computers.json`, `domain_policy.json` | DN references resolved globally; UAC flags decoded |
| SharpHound ADCS | `certtemplates`, `enterprisecas`, `rootcas`, `aiacas`, `ntauthstores`, `issuancepolicies` | incl. `CARegistryData` and DC cert-mapping registry values |
| AzureHound (v2 and v3) | `{"data":[{"kind":"AZ…","data":{…}}],"meta":{"type":"azure"}}` | all kinds mixed in one file; ids compared case-insensitively |
| LDIF (`ldapsearch`, `ldifde`) | RFC 2849, `.ldif` / `.ldf` / `.ldif.gz`, any number of files / naming contexts | detected by content; ACLs decoded from `nTSecurityDescriptor` |
| Sysinternals AD Explorer | snapshot `.dat` | memory-mapped, read in place |
| OpenGraph (BloodHound CE format, any system) | `{"metadata":{"source_kind":…},"graph":{"nodes":[…],"edges":[…]}}` | custom node and edge kinds; see [Custom data (OpenGraph)](#custom-data-opengraph) |

All inputs can be given as files, directories or `.zip` archives (zips may
contain LDIF, `.ldif.gz` and snapshots too), on the CLI or uploaded to the
server.

### Built-in LDAP collection

Under **Admin → Collectors → Built-in LDAP collection**, give CopperHound a DC
URL (`ldaps://…`, or `ldap://` with StartTLS) and a read-only account, and it
collects the domain and configuration partition (ADCS, trusts) on a schedule:
the same data as the `ldapsearch` commands below, ingested automatically.
**Test** checks connectivity and **Collect now** runs immediately.

### Raw LDAP dumps (LDIF, AD Explorer)

LDIF and snapshots produce the same graph SharpHound would for the directory
(tested against a SharpHound JSON fixture of the same domain in
`crates/ingest/tests/ldap.rs`): users / computers / groups / domains / OUs /
containers / GPOs with SharpHound ids and names, `member` + `primaryGroupID`
membership, `Contains`, ACL edges (`GenericAll`, `GenericWrite`, `WriteDacl`,
`WriteOwner`, `Owns`, `AllExtendedRights`, `ForceChangePassword`, `AddMember`,
`AddSelf`, `WriteSPN`, `AddKeyCredentialLink`, `AddAllowedToAct`,
`WriteAccountRestrictions`, `WriteGPLink`, `GetChanges*` → `DCSync`,
`ReadLAPSPassword`, `Enroll`, `WritePKI*Flag`), `ReadGMSAPassword`
(`msDS-GroupMSAMembership`), `AllowedToAct` (RBCD), `AllowedToDelegate`
(SPN host → computer), `HasSIDHistory`, `GPLink` (disabled links skipped),
`TrustedBy` (`trustedDomain`), foreign security principals and well-known SIDs
(`CORP.LOCAL-S-1-5-11`, …), and the ADCS objects of the Configuration NC
(templates with SharpHound's derived flags, enterprise / root / AIA CAs with
thumbprints and chains rebuilt from `cACertificate`, NTAuth store, issuance
policies) so the ADCS escalation passes run unchanged.

Recommended collection (OpenLDAP `ldapsearch`; one file per naming context,
paged, with the SD-flags control so non-admins receive owner + DACL):

```sh
DC=dc01.corp.local; BASE='DC=corp,DC=local'
Q="-LLL -o ldif-wrap=no -H ldap://$DC -Y GSSAPI -E pr=1000/noprompt -E !1.2.840.113556.1.4.801=::MAMCAQc="
A="* nTSecurityDescriptor msDS-GroupMSAMembership msDS-AllowedToActOnBehalfOfOtherIdentity"
ldapsearch $Q -b "$BASE" '(objectClass=*)' $A > corp-domain.ldif
ldapsearch $Q -b "CN=Configuration,$BASE" '(objectClass=*)' $A > corp-config.ldif
# optional: LAPS schema GUIDs (ReadLAPSPassword) without dumping the schema
ldapsearch $Q -b "CN=Schema,CN=Configuration,$BASE" \
  '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword))' \
  lDAPDisplayName schemaIDGUID objectClass > corp-schema.ldif
gzip *.ldif   # optional; .ldif.gz is read directly
```

(`-Y GSSAPI` can be replaced by `-x -D user@corp.local -W`. `MAMCAQc=` is the
BER value `SEQUENCE { INTEGER 7 }` = OWNER | GROUP | DACL.) For an AD Explorer
snapshot use *File → Create Snapshot* and ingest the `.dat`.

Known gaps versus SharpHound:

- No sessions, local groups, user rights or CA / DC registry data. LDAP does not
  hold them, so `HasSession`, `AdminTo`, `CanRDP` and the ESC6 / ESC9 / ESC10
  inputs are absent.
- Groups with more than 1,500 members come back from ldapsearch / ldifde as
  `member;range=0-1499` only. Fetch the remaining ranges with
  `tools/ldap-member-ranges.sh` (ldapsearch) or `tools/ldap-member-ranges.ps1`
  (Windows, no RSAT needed) and drop the output next to the dump (see
  [Importing multiple dumps](#importing-multiple-dumps)). AD Explorer is not
  affected.
- Principals referenced only by SID that are not in the dump keep kind `Unknown`.
- `CREATOR OWNER` and `PRINCIPAL SELF` ACEs are ignored.
- Template flag strings (`enrollmentflag`, `certificatenameflag`) are not
  rendered, only the derived booleans.

## Derived edges

- **AD:** `DCSync` (from `GetChanges` + `GetChangesAll`), local-group rights
  (`AdminTo`, `CanRDP`, `ExecuteDCOM`, `CanPSRemote`) from SharpHound `LocalGroups`.
- **ADCS:** `PublishedTo`, `HostsCAService`, `IssuedSignedBy`,
  `EnterpriseCAFor`, `TrustedForNTAuth`, `RootCAFor`, `NTAuthStoreFor`,
  `ExtendedByPolicy`, `OIDGroupLink`, `EnrollOnBehalfOf`,
  `DelegatedEnrollmentAgent`, and the escalations `GoldenCert`, `ADCSESC1`,
  `ESC3`, `ESC4`, `ESC6a/b`, `ESC9a/b`, `ESC10a/b`, `ESC13`. Each requires
  CA chain validity to the domain (RootCA chain + NTAuth trust + an enabled
  host), with group-level reporting of enrollment rights.
  Findings also cover what is not an edge: ESC2 (Any Purpose / no-EKU
  templates), ESC4 (template control), ESC5 (control of CA, root, NTAuth and
  issuance policy objects), ESC6 (CA SAN flag), ESC7 (CA managers) and ESC15
  / EKUwu (schema v1 templates with a supplied subject, exploitable on CAs
  without the November 2024 update). ESC8 / ESC11 (relay) are open for a
  contributor; ESC16 needs CA registry data collectors do not gather.
- **Azure:** containment, membership, ownership, role assignments, RBAC
  (`AZOwner`, `AZContributor`, `AZUserAccessAdministrator`, …), managed
  identities, key vault access, MS Graph app permissions, plus post-processed
  `AZGlobalAdmin`, `AZPrivilegedRoleAdmin`, `AZPrivilegedAuthAdmin`,
  `AZResetPassword`, `AZAddMembers`, `AZAddSecret`, `AZAddOwner`,
  `AZExecuteCommand`, `AZMG*`.
- **Hybrid:** `SyncedToEntraUser` / `SyncedToADUser` link synced Entra users to
  their AD accounts (by on-prem SID or immutable id);
  `SyncedToEntraGroup` / `SyncedToADGroup` do the same for groups.
  `EntraConnectCredentials` points from the Entra Connect server to the MSOL_ /
  Sync_ accounts, and `SeamlessSSO` from AZUREADSSOACC to the synced users it
  can impersonate. Together these let paths cross between on-prem and cloud.
- **Trusts:** `SameForestTrust` (closed over each forest), `CrossForestTrust`,
  `SpoofSIDHistory` and `AbuseTGTDelegation` (SID-filtering / TGT-delegation
  aware), and `CoerceToTGT` across the forest. See [docs/EDGES.md](EDGES.md).

## Tier Zero defaults

Tier Zero by default: well-known privileged SIDs, domains, domain controllers,
ADCS infrastructure (CAs, NTAuth store, templates, CA hosts, Cert Publishers),
Azure tenants and the Global Admin / Privileged Role Admin / Privileged Auth
Admin / Partner Tier2 / Hybrid Identity Admin / Directory Synchronization
Accounts roles, Entra Connect sync accounts and server, AZUREADSSOACC, and
legacy `highvalue`. AD and Entra Tier Zero form one target set by default
(setting `analysis.unified_tier0`). Tier Zero and owned marks can be added or
removed in the UI and persist across re-ingest.

The derivation rules follow the source-verified references in
[docs/research/](research/).

## Custom data (OpenGraph)

Data from any other system (GitHub, Okta, databases, CI, in-house tools) can be
added alongside the AD and Entra data as OpenGraph JSON, the format BloodHound
CE uses:

```json
{"metadata": {"source_kind": "GitHub"},
 "graph": {
   "nodes": [{"id": "gh-u-1", "kinds": ["GHUser"], "properties": {"name": "alice"}},
             {"id": "gh-r-1", "kinds": ["GHRepository"], "properties": {"name": "infra"}}],
   "edges": [{"kind": "GHCanPush", "start": {"value": "gh-u-1"}, "end": {"value": "gh-r-1"}},
             {"kind": "GHLinkedAccount", "start": {"value": "S-1-5-21-…-1104"},
              "end": {"value": "alice", "match_by": "name", "kind": "GHUser"}}]}}
```

- A node's kind is its first kind that is not a `Tag_*` tag. Built-in kind names
  (`User`, `Computer`, `AZUser`, …) give a built-in node, so OpenGraph records
  can also enrich collected objects (properties merge key by key). Other names
  become custom kinds (up to 192 per graph), shown with their own colour,
  searchable and usable as CHQL labels (`MATCH (n:GHRepository)`). All kinds and
  the `source_kind` are kept in the node's `kinds` property.
- Edge kinds that are not built in become custom, traversable kinds, so paths
  cross between systems (an AD user → their GitHub account → a repository that
  deploys to the domain). Edge properties are not stored.
- Edge ends match by object id (default) or by `"match_by": "name"`, optionally
  restricted to a kind; a name that matches no node or several nodes drops the
  edge (counted as `name_edges_unresolved` in the ingest report).
- `enabled: true` marks a node enabled; `Tag_Tier_Zero` (or `system_tags`
  containing `admin_tier_0`) marks it Tier Zero, `Tag_Owned` marks it owned.
- A record without `name` (or `displayname`) keeps the collected object's name;
  a new node without one is named by its id.
- OT asset inventories use this format to add Purdue levels, controllers and
  `CanProgram` edges: see [OT.md](OT.md).

## Importing multiple dumps

Every ingest reads **all** inputs together (CLI: every path given; server:
everything in the uploads directory) and builds one graph:

- **Identity.** Objects are matched by id: SIDs for users, computers, groups
  and domains (SIDs outside `S-1-5-21-…` are prefixed with the domain, e.g.
  `CORP.LOCAL-S-1-5-32-544`), objectGUIDs for OUs, GPOs, containers and ADCS
  objects, Entra object ids / ARM ids for Azure, all case-insensitively.
  Different domains, forests and tenants sit side by side, connected by their
  trusts.
- **Hybrid.** AD and Azure dumps are linked after the merge
  (`SyncedToEntraUser` / `SyncedToADUser` … by on-prem SID or immutable id),
  whichever dumps they come from.
- **The same domain twice — newest wins.** Each file (and zip entry) is a
  source with a collection time: AD Explorer snapshot time, a collector `meta`
  time, a `YYYYMMDDHHMMSS_` file-name prefix (SharpHound and bloodhound-python
  name their output this way), the zip entry time, or for LDIF the latest
  `whenChanged`. When several sources describe one object:
  - the newest collection's record defines its name, kind and flags;
  - properties merge per key (newest value wins; keys only an older collector
    wrote are kept);
  - relationships the newer record carries completely (ACEs, group members,
    sessions, local admins, containment, GPO links, trusts, Azure members /
    owners / role assignments, …) replace the older ones, so an ACE, membership
    or session removed between two collections disappears;
  - relationships the newer dump did not collect (e.g. sessions of an
    unreachable host, or a DCOnly run) keep the older data.

  Undated files and files with equal times are combined as a plain union;
  CopperHound never guesses an order. To date any file, prefix its name with
  `YYYYMMDDHHMMSS_` (UTC). Objects present only in an older dump stay, since a
  newer dump may have had a narrower scope. With the default `newest` policy,
  nodes described by several files carry `_sources` (ids into the source
  manifest, newest first). Full rules, including which record
  owns which edge type: [docs/ARCHITECTURE.md](ARCHITECTURE.md#merge-semantics).
- **Different collectors** for one domain (SharpHound + LDIF + ldapdomaindump +
  AD Explorer) merge the same way; a newer LDIF supersedes the categories it
  actually contains (e.g. `member`, `nTSecurityDescriptor`).
- **Sessions:** by default only the newest session data of each computer is
  kept; `--session-window-hours N` (server: `ingest.session_window_hours`)
  also keeps sessions seen up to N hours earlier.
- **Old behaviour:** `--merge union` (server: `ingest.merge_policy: "union"`)
  unions everything (flags OR'd, last record's properties, all edges kept).
- **Large groups in LDIF:** `member;range=X-Y` attributes and continuation
  entries for the same DN (as written by `tools/ldap-member-ranges.*`) are
  unioned into the group's membership.
- **Server: replace vs merge.** The watch folder's `replace` mode archives the
  previous uploads before importing a new drop (the graph shows only the new
  collection); `merge` mode keeps them, and the merge rules above decide what
  survives. Uploads via the UI / `POST /upload` always add to the uploads
  directory; delete old ones with `DELETE /uploads/{name}`. `GET /sources` and
  `GET /uploads` show each file's collection time, domains, object counts and
  how much of it was superseded.

The CLI prints the merge summary (`merge newest — N sources (M dated), …`);
the source manifest is stored in the graph's `meta.json` (`ingest.sources`).
