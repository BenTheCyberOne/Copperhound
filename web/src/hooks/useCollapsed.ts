import { useCallback, useState } from "react";
import { readLocal, writeLocal } from "./localStore";

/**
 * Open/closed state of named sections, persisted in localStorage under `key`.
 * Stores only the ids whose state differs from `defaultOpen`.
 */
export function useCollapsed(key: string, defaultOpen = true, initialExceptions: string[] = []) {
  const [toggled, setToggled] = useState<Set<string>>(() => {
    const raw = readLocal<unknown>(key, initialExceptions);
    return new Set(Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : []);
  });
  const toggle = useCallback(
    (id: string) =>
      setToggled((c) => {
        const next = new Set(c);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        writeLocal(key, [...next]);
        return next;
      }),
    [key],
  );
  return { isOpen: (id: string) => defaultOpen !== toggled.has(id), toggle };
}
