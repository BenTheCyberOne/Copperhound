import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useState, type ReactNode } from "react";
import { kindColor as defaultKindColor } from "../graph/kinds";
import { DEFAULT_SETTINGS, loadSettings, saveSettings, type Settings } from "./settings";

interface SettingsState {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
  reset: () => void;
  /** Theme actually applied ("system" resolved through prefers-color-scheme). */
  theme: "dark" | "light";
  /** Kind colour with the user's override applied. */
  kindColor: (kind: string) => string;
}

const Ctx = createContext<SettingsState | null>(null);

function systemTheme(): "dark" | "light" {
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(loadSettings);
  const [system, setSystem] = useState(systemTheme);

  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!mq) return;
    const onChange = () => setSystem(systemTheme());
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const theme = settings.theme === "system" ? system : settings.theme;

  // Layout effect so the attribute is set before child effects read CSS variables.
  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((s) => {
      const next = { ...s, ...patch };
      saveSettings(next);
      return next;
    });
  }, []);

  const reset = useCallback(() => {
    saveSettings(DEFAULT_SETTINGS);
    setSettings(DEFAULT_SETTINGS);
  }, []);

  const kindColor = useCallback(
    (kind: string) => settings.kindColors[kind] ?? defaultKindColor(kind),
    [settings.kindColors],
  );

  const value = useMemo(() => ({ settings, update, reset, theme, kindColor }), [settings, update, reset, theme, kindColor]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSettings(): SettingsState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSettings must be used inside SettingsProvider");
  return v;
}
