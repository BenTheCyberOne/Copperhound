// v1.5 source provenance: labels and warnings shared by the Data view, the uploads
// list and the details drawer ("Seen in").

import type { CollectedAtSource, MergePolicy, Source } from "../api/types";

/** Where the collection time came from, for display. */
export const COLLECTED_SOURCE_LABEL: Record<CollectedAtSource, string> = {
  snapshot: "snapshot header",
  meta: "collector meta",
  filename: "file-name prefix",
  "zip-entry": "zip time",
  whenchanged: "LDIF whenChanged",
};

export const COLLECTED_SOURCE_HELP: Record<CollectedAtSource | "unknown", string> = {
  snapshot: "Taken from the AD Explorer snapshot header.",
  meta: "Taken from a time field in the collector's meta block.",
  filename: "Taken from the YYYYMMDDHHMMSS_ prefix of the file name (read as UTC).",
  "zip-entry": "Taken from the zip entry's time stamp.",
  whenchanged:
    "Lower bound: the latest LDAP whenChanged in the file. The export was taken at this time or later. Prefix the file name with YYYYMMDDHHMMSS_ to set the real time.",
  unknown: "No collection time found. The file is merged as a plain union. Prefix the file name with YYYYMMDDHHMMSS_ (UTC) to date it.",
};

export function collectedSourceLabel(s: CollectedAtSource | null): string {
  return s ? COLLECTED_SOURCE_LABEL[s] : "unknown";
}

export function collectedSourceHelp(s: CollectedAtSource | null): string {
  return COLLECTED_SOURCE_HELP[s ?? "unknown"];
}

export const MERGE_POLICY_HELP: Record<MergePolicy, string> = {
  newest: "Newest collection wins per object; relationships it lists replace older ones.",
  union: "Plain union: flags OR'd, last record's properties, every edge kept.",
};

/** "file › entry" */
export function sourceName(s: Pick<Source, "file" | "entry">): string {
  return s.entry ? `${s.file} › ${s.entry}` : s.file;
}

export interface SourceWarning {
  id: "undated" | "lower-bound";
  label: string;
  title: string;
}

const UNDATED: SourceWarning = {
  id: "undated",
  label: "undated",
  title: "Merged as union: prefix the file name with YYYYMMDDHHMMSS_ to order it.",
};

/**
 * Warnings for one source, given every source of the graph: undated sources, and LDIF
 * sources dated only by `whenChanged` (a lower bound) next to SharpHound data of the same domain.
 */
export function sourceWarnings(s: Source, all: Source[]): SourceWarning[] {
  const out: SourceWarning[] = [];
  if (s.collected_at_unix === null || s.collected_at === null) out.push(UNDATED);
  if (s.collected_at_source === "whenchanged") {
    const mine = new Set(s.domains.map((d) => d.toUpperCase()));
    const mixed = all.filter((o) => o.format === "sharphound" && o.domains.some((d) => mine.has(d.toUpperCase())));
    if (mixed.length > 0) {
      const domains = [...new Set(mixed.flatMap((o) => o.domains).filter((d) => mine.has(d.toUpperCase())))];
      out.push({
        id: "lower-bound",
        label: "lower-bound time",
        title:
          `This LDIF is dated by its latest whenChanged, a lower bound, but SharpHound data of ${domains.join(", ")} is also loaded. ` +
          "The LDIF may lose to an older SharpHound collection. Prefix its file name with YYYYMMDDHHMMSS_ (UTC export time) to order it correctly.",
      });
    }
  }
  return out;
}
