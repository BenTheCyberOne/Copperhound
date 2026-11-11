// User preferences, persisted in localStorage. Unknown or invalid stored values fall
// back to defaults field by field so old or hand-edited storage never breaks the app.

import { readLocal, writeLocal } from "../hooks/localStore";

export type ThemeSetting = "dark" | "light" | "system";
export type NodeSizeMode = "fixed" | "degree";
export type LabelMode = "auto" | "always" | "hover" | "selected" | "off";
export type PathHighlight = "accent" | "bold" | "thick";
export type LayoutMode = "force" | "hierarchical-lr" | "hierarchical-tb" | "circular" | "grid";

export interface Fa2Settings {
  gravity: number;
  scalingRatio: number;
  linLogMode: boolean;
  durationMs: number;
}

export interface Settings {
  // Appearance
  theme: ThemeSetting;
  kindColors: Record<string, string>;
  nodeSize: NodeSizeMode;
  labelMode: LabelMode;
  edgeLabels: boolean;
  edgeCurves: boolean;
  pathHighlight: PathHighlight;
  // Canvas filters
  hiddenNodeKinds: string[];
  hiddenEdgeKinds: string[];
  hideNonTraversable: boolean;
  dimOffPath: boolean;
  /** Zone ids whose membership ring is not drawn (Tier Zero has its own ring). */
  hiddenZoneRings: string[];
  // Layout
  layout: LayoutMode;
  autoLayout: boolean;
  fa2: Fa2Settings;
  // Behaviour
  queryLimit: number;
  /** 0 = use the server default */
  queryTimeoutMs: number;
  replaceByDefault: boolean;
  maxNodes: number;
  confirmClear: boolean;
}

export const NODE_CAP_DEFAULT = 5000;
export const NODE_CAP_MAX = 20000;

export const DEFAULT_SETTINGS: Settings = {
  theme: "dark",
  kindColors: {},
  nodeSize: "fixed",
  labelMode: "auto",
  edgeLabels: false,
  edgeCurves: false,
  pathHighlight: "accent",
  hiddenNodeKinds: [],
  hiddenEdgeKinds: [],
  hideNonTraversable: false,
  dimOffPath: false,
  hiddenZoneRings: ["tier0"],
  layout: "force",
  autoLayout: true,
  fa2: { gravity: 1, scalingRatio: 10, linLogMode: false, durationMs: 3000 },
  queryLimit: 1000,
  queryTimeoutMs: 0,
  replaceByDefault: false,
  maxNodes: NODE_CAP_DEFAULT,
  confirmClear: true,
};

const KEY = "copperhound.settings";

const oneOf = <T extends string>(v: unknown, options: readonly T[], d: T): T =>
  typeof v === "string" && (options as readonly string[]).includes(v) ? (v as T) : d;
const bool = (v: unknown, d: boolean) => (typeof v === "boolean" ? v : d);
const num = (v: unknown, d: number, min: number, max: number) =>
  typeof v === "number" && Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : d;
const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

function sanitize(raw: unknown): Settings {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const d = DEFAULT_SETTINGS;
  const fa2 = (r.fa2 && typeof r.fa2 === "object" ? r.fa2 : {}) as Record<string, unknown>;
  const colors: Record<string, string> = {};
  if (r.kindColors && typeof r.kindColors === "object") {
    for (const [k, v] of Object.entries(r.kindColors as Record<string, unknown>)) {
      if (typeof v === "string" && /^#[0-9a-f]{6}$/i.test(v)) colors[k] = v;
    }
  }
  return {
    theme: oneOf(r.theme, ["dark", "light", "system"], d.theme),
    kindColors: colors,
    nodeSize: oneOf(r.nodeSize, ["fixed", "degree"], d.nodeSize),
    labelMode: oneOf(r.labelMode, ["auto", "always", "hover", "selected", "off"], d.labelMode),
    edgeLabels: bool(r.edgeLabels, d.edgeLabels),
    edgeCurves: bool(r.edgeCurves, d.edgeCurves),
    pathHighlight: oneOf(r.pathHighlight, ["accent", "bold", "thick"], d.pathHighlight),
    hiddenNodeKinds: strings(r.hiddenNodeKinds),
    hiddenEdgeKinds: strings(r.hiddenEdgeKinds),
    hideNonTraversable: bool(r.hideNonTraversable, d.hideNonTraversable),
    dimOffPath: bool(r.dimOffPath, d.dimOffPath),
    hiddenZoneRings: Array.isArray(r.hiddenZoneRings) ? strings(r.hiddenZoneRings) : d.hiddenZoneRings,
    layout: oneOf(r.layout, ["force", "hierarchical-lr", "hierarchical-tb", "circular", "grid"], d.layout),
    autoLayout: bool(r.autoLayout, d.autoLayout),
    fa2: {
      gravity: num(fa2.gravity, d.fa2.gravity, 0, 50),
      scalingRatio: num(fa2.scalingRatio, d.fa2.scalingRatio, 0.1, 200),
      linLogMode: bool(fa2.linLogMode, d.fa2.linLogMode),
      durationMs: num(fa2.durationMs, d.fa2.durationMs, 500, 30000),
    },
    queryLimit: num(r.queryLimit, d.queryLimit, 1, 100000),
    queryTimeoutMs: num(r.queryTimeoutMs, d.queryTimeoutMs, 0, 3_600_000),
    replaceByDefault: bool(r.replaceByDefault, d.replaceByDefault),
    maxNodes: num(r.maxNodes, d.maxNodes, 100, NODE_CAP_MAX),
    confirmClear: bool(r.confirmClear, d.confirmClear),
  };
}

export function loadSettings(): Settings {
  return sanitize(readLocal<unknown>(KEY, {}));
}

export function saveSettings(s: Settings): void {
  writeLocal(KEY, s);
}
