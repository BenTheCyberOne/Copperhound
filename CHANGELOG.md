# Changelog

Notable changes to CopperHound. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
