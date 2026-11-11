# CopperHound web UI

The browser front end for CopperHound: a single-page app built with Vite, React 18 and
TypeScript, drawing graphs with sigma.js v3 (WebGL) on top of graphology. The production
build is static files that the CopperHound server serves at `/`. All API calls go to the
relative path `/api/v1` ([`docs/API.md`](../docs/API.md)).

## Requirements

Node 18 or newer (developed with Node 24).

## Commands

```sh
npm install          # install the pinned dependencies
npm run dev          # dev server on http://localhost:5173, proxies /api to http://127.0.0.1:8080 (or $COPPERHOUND_API)
npm run dev:mock     # dev server with the in-browser mock API (no backend needed)
npm run build        # typecheck (tsc), then build static files into web/dist
npm run preview      # serve the built dist/ locally
npm run typecheck    # tsc only
npm run lint         # eslint
```

### Mock mode

`npm run dev:mock` starts Vite in `mock` mode, which loads `.env.mock` to set
`VITE_MOCK=1` (you can also set it yourself). Every API call is then answered in the
browser by `src/mock/`, using a sample environment of about 70 objects: the CORP.LOCAL
domain with users, groups, computers, OUs and GPOs, an ADCS CA with templates (including
an ESC1 template), and a small Entra ID tenant. The mock includes a small CHQL interpreter (including `days_ago`), path finding with hops, the Tier Zero report,
31 tagged prebuilt queries, in-memory saved queries, query timeout and cancel (path queries
are slowed on purpose so you can try Cancel), uploads, and ingest jobs with phases. Each
rebuild bumps the graph generation, so you can try the stale-canvas banner.

Sign in as `admin` / `copperhound`, `analyst` / `analyst-password` or `viewer` / `viewer-password`
to see role gating. Five wrong passwords lock an account for 5 minutes, as on the server.

The mock is loaded with a dynamic `import()` guarded by `import.meta.env.VITE_MOCK`, so a
normal `npm run build` leaves it out of `dist/` completely.

## Views

The left rail switches between views. Each view has a shareable URL hash, for example
`#/findings/dcsync-non-tier0`, `#/zones/<id>`, `#/posture?from=<snapshot>&to=<snapshot>`
or `#/settings/filters`.

- **Explore**: the graph canvas with the Path, Queries and Exposure tabs, plus the details
  drawer. Right-click a node or an edge to add it to the what-if fix list. Members of zones
  get a ring in the zone's colour; each zone's ring can be turned on or off under Settings →
  Canvas filters.
- **Findings**:
  - Severity cards, filters and sorting.
  - Exposure impact for each finding and its MITRE ATT&CK ids.
  - A detail page with the remediation text and the detection query ("open in editor").
  - Paginated items you can show on the canvas or simulate fixing, and CSV export.
- **Remediation**:
  - What-if simulator: the fix list is kept in localStorage, and node ids are re-resolved by
    objectid after a rebuild.
  - Planner: dominator-tree steps, a cumulative reduction chart, CSV export.
- **Posture**: snapshot history charts, the snapshot table, and a diff between two snapshots.
- **Zones**: create, edit and delete privilege zones with a CHQL selector. Each zone shows its
  members, exposure and choke points.
- **Data**: uploads, rebuilds and jobs. Each job shows what started it (manual, watch or api).
- **Reports**: download the assessment as HTML, Markdown or CSV, or open the HTML report in a
  new tab (use Print → Save as PDF there to get a PDF). The report is fetched as a blob because
  the request needs the bearer header.
- **Account** (user menu): profile, password change, personal API tokens. A new token is shown
  only once.
- **Admin** (admins only): users and roles, the audit log, and server settings (the watch
  folder plus its live status).

Roles are viewer < analyst < admin. The UI disables or hides actions your role cannot perform,
with a tooltip naming the role you need. Any 403 from the server is shown as a toast with the
server's message.

Analysis endpoints answer `202 computing` for a while after a rebuild; the views show progress
and retry automatically. The mock does the same for about 6 s after a mock ingest.

## Layout of the source

```
src/
  api/          types.ts (mirrors docs/API.md), client.ts (typed client, auth token, 401 handling, XHR upload)
  mock/         in-browser backend for mock mode (data, traversal, CHQL subset, routes)
  state/        AppContext (selection, canvas actions, stale-canvas reload), CatalogContext (/health polling, categorised kinds)
  settings/     persisted user settings, settings dialog, canvas filters
  graph/        GraphStore (graphology), sigma renderer, ForceAtlas2 worker + layered layout,
                canvas, legend, context menu, kind colours
  components/   top bar, sidebar, details drawer, node picker (autocomplete), tables, login
  tabs/         Path, Exposure; queries/ (editor with cancel, library, saved queries)
  views/        Findings, Remediation (simulator, planner), Posture, Zones, Data
  util/         CSV export
  hooks/        hash router, analysis loader with 202 retry, debounce, localStorage helpers
```

## Notes

- The session token lives in `sessionStorage`. Any 401 response sends you back to the login
  screen.
- Settings (gear icon in the top bar) are stored in `localStorage` under `copperhound.settings`
  and have a reset button. They cover:
  - Appearance: theme, colour per node kind, node size, label mode, edge labels, curved
    edges, path highlight style.
  - Canvas filters: hide node or edge kinds, hide non-traversable edges, dim everything off
    the highlighted path.
  - Layout: ForceAtlas2, hierarchical (left to right or top to bottom), circular or grid;
    ForceAtlas2 tuning; automatic layout on or off.
  - Behaviour: query limit and timeout, merge or replace by default, node render cap
    (default 5000, up to 20000), confirmation before clearing the canvas.
- Favourite queries, recent queries, the open or closed state of collapsible sections and the
  legend are also kept in `localStorage`. Saved queries ("My queries") are stored on the
  server.
- `/health` is polled every 30 s. When the graph generation changes, the canvas shows a
  "Graph was rebuilt" banner. "Reload canvas" finds each canvas node again by objectid and
  redraws it in the same position.
- Running queries send a `query_id`, so the Cancel button can stop them
  (`DELETE /query/{id}`).

If you add files, keep file names unique ignoring case: Windows and macOS file systems treat
names that differ only in case as the same file.
