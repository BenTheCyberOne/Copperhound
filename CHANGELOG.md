# Changelog

Notable changes to CopperHound. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.1] - 2026-11-17

### Fixed

- The remediation planner never proposes a Tier Zero object as a fix. For zones other than Tier Zero it
  could suggest removing, say, Domain Admins' rights over its own members, which also inflated
  weighted plans and the report's cross-zone figure.
- Tier Zero objects no longer count as exposed principals of other zones (zone exposure, plans, finding
  impact against other targets): whoever holds Tier Zero already controls every zone.
- Planner and posture chart axes no longer repeat "1%" when values are small.

## [0.4.0] - 2026-11-17

NTLM relay paths, sessions from logon data and cost-aware paths.

### Added

- NTLM relay edges, as in BloodHound CE: `CoerceAndRelayNTLMToSMB`, `CoerceAndRelayNTLMToLDAP`,
  `CoerceAndRelayNTLMToLDAPS`, `CoerceAndRelayNTLMToADCS` (ESC8) and `CoerceAndRelayNTLMToADCSRPC`
  (ESC11), from Authenticated Users to each coercible computer, with edge composition naming the relay
  target. SharpHound's `SmbInfo`, `IsWebClientRunning`, `NTLMRegistryData`, `HttpEnrollmentEndpoints`
  and CA RPC encryption data are now read.
- `ADCSESC16` (CA with the SID security extension disabled and requester-specified SANs).
- `WriteAltSecurityIdentities` (ESC14A), `DCFor`, `DumpSMSAPassword`, `SQLAdmin`,
  `ClaimSpecialIdentity` and `ProtectAdminGroups` (not traversable). The LDAP reader derives
  `WritePublicInformation`, `WriteAltSecurityIdentities`, `DumpSMSAPassword` and `SQLAdmin` too.
- Findings: `ntlm-relay-tier0`, `ntlm-relay-adcs`, `ntlm-relay-ldap`, `ntlm-relay-smb`,
  `adcs-web-enrollment-relay`, `dc-ldap-relay`, `smb-signing-off`, `adminsdholder-control`.
- Built-in LDAP collector: opt-in network probes per target (SMB signing, DC LDAP signing, AD CS web
  enrollment over HTTP) and an "assume outgoing NTLM allowed" option.

- Sessions from logon data: `scripts/Export-CopperHoundLogons.ps1` (Security event 4624, local or
  forwarded) and Microsoft Defender XDR `DeviceLogonEvents` (JSON or CSV upload). Only logon types
  that leave credentials count; endpoints must already be in the graph.
- Session times: each `HasSession` edge records when it was first and last seen, by which source and
  with which logon types (`sessions.bin`). CHQL `r.lastseen`, `r.firstseen`, `r.sessionsources`,
  `r.logontypes`; `GET /edges/session`; shown in the edge details.
- Cost-aware paths: **Optimise for** fewest hops, least effort or stealthiest in the Path tab
  (`POST /path` `cost`, CLI `path --cost`). Edge costs per kind and profile, a session-age penalty,
  admin overrides (`GET/PUT /path-costs`), and **Cheapest routes to Tier Zero** in the Exposure tab
  (`GET /tier0/cheapest`).
- `session_max_age_days` ingest setting (CLI `--session-max-age-days`): sessions not seen recently stop
  counting as attack paths.

### Changed

- Members of Tier Zero groups are Tier Zero (transitively, not through Domain Users, Authenticated
  Users, Everyone and similar broad groups). Exposure no longer counts Domain Admins members as exposed
  principals; control over them shows up in `tier0-control`.
- `WritePublicInformation` is traversable (ESC14A): exposure can rise for existing data. Built-in edge
  traversability now follows the running release for graphs written earlier.
- New relay and AD edges need a re-ingest of existing data to appear.

### Fixed

- Data page: Data quality no longer leaves a gap under Loaded graph; Database management spans the page.
- Data quality lists each problem once with the affected domains and its advice, tells tenants that share a
  name apart by id, and explains objects of unknown kind (`/quality`: `warning_codes`, `advice`,
  `unknown_objects`; warnings are now short facts).
- The navigation rail fits windows down to 900 px high; the Explore toolbar stays on one row with the details
  drawer open.
- Posture: the exposure chart axis fits small percentages.
- Zone header spacing, the Users role cards and the SSO status tag.
- Node details hide empty properties behind "Show N empty"; Exposure collapses kinds with no path.
- Ingest job messages use thousands separators; collector and server settings text mention logon data.
- The web UI is served with cache headers (`no-cache` for the page, long-lived for hashed assets), so an
  upgrade shows without a hard refresh.

## [0.3.0] - 2026-11-13

Zone weights and cross-zone planning.

### Added

- **Cross-zone remediation plans**. Zones have a weight (0-100, default 1;
  Tier Zero included). **All zones, by weight** in the remediation planner
  picks, at each step, the fix that cuts the most weighted exposure (weight ×
  principals cut off, summed over zones) and shows the cut per zone.
  `PUT /zones/{id}/weight`, `"weighted": true` on `POST /remediation-plan`,
  and `copperhound plan --zone NAME=WEIGHT:SELECTOR --tier0-weight N`.
- **Add to zone…** on the canvas context menu and the details drawer puts
  objects into a zone by hand, or starts a new zone with them. Hand-added
  objects are members whatever the selector matches and are certified in
  zone review; a zone's selector may now be empty.
  `POST /zones/{id}/objects`.
- Zone templates for infrastructure (domain controllers, PKI, member
  servers, backup), risky accounts and hosts (unconstrained delegation,
  service accounts, operators, `adminCount`) and the cloud (Azure control
  plane, key vaults), grouped by category in **Start from a template**.
- Reports (HTML and Markdown, including scheduled ones) have a **Zones**
  section with exposure per zone and the cross-zone plan, when custom zones
  exist. `copperhound report --zone …` does the same from the command line.

### Fixed

- On the canvas, a node kept following the mouse after a right-click
  (for example after **Add to zone…**).

## [0.2.0] - 2026-11-13

OT support and bug fixes.

### Added

- **Operational technology (OT)**. See [docs/OT.md](docs/OT.md).
  - Built-in `CanProgram` edge (new "OT" category) for engineering
    workstations or accounts that can program a controller. It is supplied as
    OpenGraph from an OT asset inventory.
  - `purdue_level` and `ot_role` properties. 14 OT / ICS library queries. OT
    zone templates in **Zones → New zone**.
  - Five OT findings: IT access to engineering workstations, IT access to OT
    hosts, legacy Windows, missing LAPS and enabled vendor accounts. Their
    impact is measured against OT controllers instead of Tier Zero.
  - `scripts/demo_data.py --ot` adds a fabricated production site.
- **Fix cost**. A `fix_cost` node property (`window` or `fixed`) lets the
  remediation planner skip objects that must not change and flag steps that
  need a maintenance window. It adds **Fixes that need no maintenance window
  first** in the planner and `copperhound plan --live-first`.
- **Network reachability**. Hosts get a `net_zone` property, and firewall
  conduits between zones are set under **Admin → Server → Network conduits**.
  Paths can then follow only routes the network allows: **Only paths the
  network allows** in the Path tab, `--conduits` on `copperhound path` /
  `tier0`, `GET /network/exposure` and `"network": true` on `POST /path`.
- `CHANGELOG.md`.

### Changed

- Findings name what their impact is measured against (`exposure.target`:
  "Tier Zero" or "OT controllers"), in the API, UI, CLI and reports.
- The `legacy-os` finding and query also flag Windows 2000, 8 / 8.1,
  Embedded Standard 7 and Server 2012 / 2012 R2.
- In CHQL, a comparison with `null` is never true: `x = null` and
  `{key: null}` match nothing (`IS NULL` tests for null).
- In CHQL, variable-length relationships (`*min..max`) return every node
  reachable by a walk of `min..max` hops. Before, only nodes whose shortest
  distance was in range were returned.

### Fixed

- **Security** (from an internal review)
  - CHQL: a long chain of operators (`1+1+…`, `… OR … OR …`) overflowed the
    stack and stopped the server. Chains now count toward the nesting limit.
  - CHQL: list comprehensions, quantifiers and `range()` ignored the query
    timeout. Lists and strings a query builds are now limited by a memory
    budget, and over-large queries fail with `too_large`.
  - Ingest: a 3-byte file (`[}]`) made ingest loop forever.
  - Ingest: zip and gzip decompression bombs are refused. Entries may expand
    at most 200x (64 MiB floor). Zips with over 100,000 entries are refused.
  - Ingest: crafted AD Explorer snapshots no longer use memory quadratic in
    their size.
  - Reports: custom node kind names were not escaped in the HTML and Markdown
    reports. The HTML report now carries its own Content-Security-Policy.
  - Remediation commands: names containing typographic quotes (U+2018 to
    U+201B) could break out of PowerShell strings.
  - BloodHound-signed requests: the body read before the signature check is
    capped (`COPPERHOUND_MAX_SIGNED_BODY_MB`), and spool files are always
    removed.
  - Webhook URLs no longer appear in delivery errors or, for non-admins, in
    `GET /tickets/targets`.
  - Stored ticketing, SMTP and LDAP passwords are no longer reused when a
    target is pointed at another server, or when its TLS settings are
    weakened.
  - SSO: the sign-in exchange code is bound to the browser that completed
    sign-in, which prevents login CSRF.
  - Disabling 2FA with a wrong code is rate-limited like sign-in.
  - `/api/v2/login`, backup downloads and audit-log reads are recorded in the
    audit log.
  - Graph files are validated on open, so a corrupt file is refused instead
    of crashing the server later.
  - Ticket links returned by a webhook are shown only when they are
    `http(s)` URLs.
- OpenGraph records without a `name` replaced the collected object's name with
  its id.
- BloodHound-signed uploads larger than 8 MiB failed.
- CHQL: `WHERE n.kind = 'X'` returned no rows for custom (OpenGraph) kinds.
- CHQL: `shortestPath` gave different results depending on the number of
  start nodes when a start was also a target. `allShortestPaths` dropped such
  starts.
- Ingest: graphs with tens of thousands of custom relationship kinds ingested
  very slowly. Kinds beyond the registry limit were turned into `GenericAll`;
  they are now dropped and reported.
- The CLI printed custom node kinds as `Unknown`.

## [0.1.0] - 2026-11-11

First public release.

- Rust workspace and a single binary. Ingests SharpHound (v4 to v6, CE),
  bloodhound-python, AzureHound, ldapdomaindump, LDIF, AD Explorer snapshots
  and OpenGraph data into a memory-mapped graph store. No graph database is
  needed.
- CHQL, a read-only Cypher dialect, with 159 prebuilt queries.
- Findings measured by exposure impact, a what-if simulator, a dominator-tree
  remediation planner, and hand-off to PowerShell, Jira, ServiceNow or a
  webhook.
- Privilege zones, posture over time, change alerts and scheduled reports.
- Web UI and REST API, with OIDC and SAML sign-on, 2FA, API tokens and a
  BloodHound-compatible upload API.
