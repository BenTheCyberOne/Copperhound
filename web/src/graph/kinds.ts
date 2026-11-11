import { ADCS_KINDS, AD_KINDS, AZURE_KINDS, KIND_CATEGORIES, type KindCategory, type KindStyle, type NodeKind } from "../api/types";

/** Categories as used by the API (/node-kinds, /edge-kinds); "Other" also covers unknown kinds. */
export type Category = KindCategory;
export const CATEGORY_ORDER: Category[] = [...KIND_CATEGORIES];

// Families use separate hue bands so the canvas reads at a glance:
// AD = warm/green, ADCS = magenta/rose, Azure = blue/cyan/indigo.
const COLORS: Record<NodeKind, string> = {
  User: "#22c55e",
  Group: "#eab308",
  Computer: "#f97316",
  Domain: "#14b8a6",
  GPO: "#8b5cf6",
  OU: "#c8a26b",
  Container: "#8d8579",

  CertTemplate: "#ec4899",
  EnterpriseCA: "#d946ef",
  RootCA: "#c026d3",
  AIACA: "#f0abfc",
  NTAuthStore: "#fb7185",
  IssuancePolicy: "#f9a8d4",

  AZTenant: "#2563eb",
  AZUser: "#60a5fa",
  AZGroup: "#93c5fd",
  AZApp: "#38bdf8",
  AZServicePrincipal: "#0ea5e9",
  AZDevice: "#2dd4bf",
  AZRole: "#818cf8",
  AZSubscription: "#6366f1",
  AZResourceGroup: "#7dd3fc",
  AZManagementGroup: "#4f46e5",
  AZKeyVault: "#0d9488",
  AZVM: "#5eead4",
  AZAutomationAccount: "#a5b4fc",
  AZContainerRegistry: "#67e8f9",
  AZFunctionApp: "#06b6d4",
  AZLogicApp: "#0891b2",
  AZManagedCluster: "#4338ca",
  AZVMScaleSet: "#99f6e4",
  AZWebApp: "#22d3ee",

  Unknown: "#6b7280",
};

export const OWNED_RING_COLOR = "#ef4444";

/** Custom (OpenGraph) kinds get a stable colour from their name. */
function customColor(kind: string): string {
  let h = 2166136261;
  for (let i = 0; i < kind.length; i++) h = Math.imul(h ^ kind.charCodeAt(i), 16777619);
  // HSL(hue, 62%, 58%) as hex: the canvas renderer only parses hex / rgb().
  const hue = (h >>> 0) % 360;
  const sat = 0.62;
  const light = 0.58;
  const c = (1 - Math.abs(2 * light - 1)) * sat;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = light - c / 2;
  const [r, g, b] = hue < 60 ? [c, x, 0] : hue < 120 ? [x, c, 0] : hue < 180 ? [0, c, x] : hue < 240 ? [0, x, c] : hue < 300 ? [x, 0, c] : [c, 0, x];
  const hex = (v: number) => Math.round((v + m) * 255).toString(16).padStart(2, "0");
  return `#${hex(r)}${hex(g)}${hex(b)}`;
}

/** Organisation-wide styles (GET /kind-styles), set once loaded. */
let shared: Record<string, KindStyle> = {};

export function setSharedKindStyles(s: Record<string, KindStyle>): void {
  shared = s;
}

/** Shared icon (emoji / letters) of a kind, if any. */
export function kindIcon(kind: string): string | undefined {
  return shared[kind]?.icon || undefined;
}

export function kindColor(kind: string): string {
  return shared[kind]?.color ?? COLORS[kind as NodeKind] ?? (kind && kind !== "Unknown" ? customColor(kind) : COLORS.Unknown);
}

/** Static fallback for node kinds missing from /node-kinds. */
export function fallbackNodeCategory(kind: string): Category {
  if ((AD_KINDS as readonly string[]).includes(kind)) return "Active Directory";
  if ((ADCS_KINDS as readonly string[]).includes(kind)) return "ADCS";
  if ((AZURE_KINDS as readonly string[]).includes(kind)) return "Azure";
  return kind === "Unknown" ? "Other" : "Custom";
}

/** Short label used in kind badges. */
export function kindShort(kind: string): string {
  return kind.startsWith("AZ") ? `AZ ${kind.slice(2)}` : kind;
}
