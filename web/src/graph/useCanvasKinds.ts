import { useSyncExternalStore } from "react";
import type { ChecklistItem } from "../components/CategoryChecklist";
import { useSettings } from "../settings/SettingsContext";
import { useCatalog } from "../state/CatalogContext";
import type { GraphStore } from "./store";

/** Node and edge kinds present on the canvas, categorised, with on-canvas counts. */
export function useCanvasKinds(store: GraphStore): { nodeItems: ChecklistItem[]; edgeItems: ChecklistItem[] } {
  useSyncExternalStore(store.subscribe, store.version);
  const { nodeCategory, edgeCategory, isTraversable } = useCatalog();
  const { kindColor } = useSettings();
  const nodeItems = [...store.kinds()].map(([name, count]) => ({
    name,
    count,
    category: nodeCategory(name),
    color: kindColor(name),
  }));
  const edgeItems = [...store.edgeKinds()].map(([name, count]) => ({
    name,
    count,
    category: edgeCategory(name),
    muted: !isTraversable(name),
  }));
  return { nodeItems, edgeItems };
}
