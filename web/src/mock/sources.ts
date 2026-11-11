// v1.5 source manifest for mock mode: every upload becomes one source per file / zip
// entry, dated like the server does it (file-name prefix, LDIF whenChanged, undated),
// with "newest wins" superseded counts per domain and object type.

import type { CollectedAtSource, MergePolicy, Source, SourcesResponse, UploadInfo } from "../api/types";
import type { MockNode } from "./data";

const DOMAIN = "CORP.LOCAL";
const TENANT_ID = "6f1c2a4e-9b8d-4e1a-8c3f-2d7b5a9e0c41";
const SHARPHOUND_KINDS = ["users", "groups", "computers", "domains", "gpos", "ous", "containers"];
const PREFIX = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})_/;

interface Manifest {
  merge_policy: MergePolicy;
  superseded_objects: number;
  superseded_edges: number;
  sources: Source[];
}

let manifest: Manifest = { merge_policy: "newest", superseded_objects: 0, superseded_edges: 0, sources: [] };

/** Deterministic pseudo-random count from a string. */
function hashCount(s: string, min: number, max: number): number {
  let h = 2166136261;
  for (const c of s) h = Math.imul(h ^ c.charCodeAt(0), 16777619);
  return min + ((h >>> 0) % (max - min + 1));
}

function prefixTime(name: string): string | null {
  const m = PREFIX.exec(name);
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z` : null;
}

type Draft = Omit<Source, "id" | "superseded_objects" | "superseded_edges">;

function draft(file: string, entry: string | null, format: string, kind: string | null, domains: string[], at: string | null, how: CollectedAtSource | null, mtime: string): Draft {
  const key = `${file}/${entry ?? ""}`;
  const objects = hashCount(key, 4, 60);
  return {
    file,
    entry,
    format,
    kind,
    domains,
    collected_at: at,
    collected_at_unix: at ? Math.floor(Date.parse(at) / 1000) : null,
    collected_at_source: at ? how : null,
    file_mtime: mtime,
    records: objects,
    objects,
    edges: objects * hashCount(key + "e", 2, 9),
    parse_errors: format === "json" ? 1 : 0,
  };
}

/** Sources one upload yields, by its name (the mock has no file contents). */
function sourcesOf(u: UploadInfo): Draft[] {
  const name = u.name;
  const lower = name.toLowerCase();
  const at = prefixTime(name);
  if (lower.endsWith(".zip")) {
    if (lower.includes("azure")) return [draft(name, "azurehound.json", "azurehound", null, [TENANT_ID], null, null, u.uploaded_at)];
    // SharpHound names entries like the archive: <stamp>_users.json.
    const stamp = PREFIX.exec(name)?.[0] ?? "";
    return SHARPHOUND_KINDS.map((k) => draft(name, `${stamp}${k}.json`, "sharphound", k, [DOMAIN], at, "filename", u.uploaded_at));
  }
  if (/\.(ldif|ldf)(\.gz)?$/.test(lower)) {
    // Dated by the latest whenChanged unless the name has a prefix.
    const lowerBound = new Date(Date.parse(u.uploaded_at) - 3 * 86400_000).toISOString().replace(/\.\d+Z$/, "Z");
    return [draft(name, null, "ldif", null, [DOMAIN], at ?? lowerBound, at ? "filename" : "whenchanged", u.uploaded_at)];
  }
  if (lower.endsWith(".dat")) return [draft(name, null, "adexplorer", null, [DOMAIN], u.uploaded_at, "snapshot", u.uploaded_at)];
  if (lower.includes("azure")) return [draft(name, null, "azurehound", null, [TENANT_ID], at, at ? "filename" : null, u.uploaded_at)];
  const kind = SHARPHOUND_KINDS.find((k) => lower.includes(k)) ?? null;
  return [draft(name, null, kind ? "sharphound" : "json", kind, kind ? [DOMAIN] : [], at, at ? "filename" : null, u.uploaded_at)];
}

/** Rebuilds the manifest from the uploads present at ingest time. */
export function buildManifest(uploads: UploadInfo[], policy: MergePolicy): Manifest {
  const drafts = [...uploads].sort((a, b) => a.name.localeCompare(b.name)).flatMap(sourcesOf);
  const sources: Source[] = drafts.map((d, id) => ({ ...d, id, superseded_objects: 0, superseded_edges: 0 }));
  if (policy === "newest") {
    // Within one domain and object type, dated sources older than the newest lose most of their records.
    const groups = new Map<string, Source[]>();
    for (const s of sources) {
      if (s.collected_at_unix === null) continue;
      const key = `${s.domains.join(",")}|${s.kind ?? s.format}`;
      groups.set(key, [...(groups.get(key) ?? []), s]);
    }
    for (const g of groups.values()) {
      const newest = Math.max(...g.map((s) => s.collected_at_unix!));
      for (const s of g) {
        if (s.collected_at_unix! < newest) {
          s.superseded_objects = Math.round(s.objects * 0.9);
          s.superseded_edges = Math.round(s.edges * 0.7);
        }
      }
    }
  }
  manifest = {
    merge_policy: policy,
    superseded_objects: sources.reduce((a, s) => a + s.superseded_objects, 0),
    superseded_edges: sources.reduce((a, s) => a + s.superseded_edges, 0),
    sources,
  };
  return manifest;
}

export function sourcesResponse(generation: number): SourcesResponse {
  return { generation, ...manifest };
}

/** GET /uploads entries with `in_graph` and the sources each file produced. */
export function uploadsWithSources(uploads: UploadInfo[]): UploadInfo[] {
  return uploads.map((u) => {
    const sources = manifest.sources.filter((s) => s.file === u.name);
    return { ...u, in_graph: sources.length > 0, sources };
  });
}

/**
 * `_sources` for a node: AD objects of the SharpHound kind present in several dated
 * collections, newest first (at most 4), like the server's manifest ids.
 */
export function nodeSources(n: MockNode): number[] | null {
  const kind = `${n.kind.toLowerCase()}s`;
  const domainMatch = (s: Source) => s.domains.includes(String(n.properties.domain ?? "").toUpperCase());
  const ids = manifest.sources
    .filter((s) => domainMatch(s) && (s.kind === kind || s.format === "ldif" || s.format === "adexplorer"))
    .sort((a, b) => (b.collected_at_unix ?? -1) - (a.collected_at_unix ?? -1))
    .map((s) => s.id);
  // Some users exist in one collection only (no `_sources`).
  if (ids.length < 2 || (n.kind === "User" && n.id % 3 === 2)) return null;
  return ids.slice(0, 4);
}
