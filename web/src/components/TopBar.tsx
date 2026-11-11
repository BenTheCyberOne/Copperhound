import { useState } from "react";
import { isMockMode } from "../api/client";
import { navigate } from "../hooks/useRoute";
import type { Node } from "../api/types";
import { useSettings } from "../settings/SettingsContext";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";
import { KindSelect } from "./KindSelect";
import { Logo } from "./Logo";
import { NodePicker } from "./NodePicker";
import { UserMenu } from "./UserMenu";

export function TopBar({ onLogout }: { onLogout: () => void }) {
  const { loadResult, select, store, busy } = useApp();
  const { health } = useCatalog();
  const { theme, update } = useSettings();
  const [kind, setKind] = useState("");

  const pick = (n: Node) => {
    navigate("explore");
    if (store.has(n.id)) {
      select(n.id);
      return;
    }
    loadResult({ nodes: [n], edges: [], truncated: false, elapsed_ms: 0 }, { forceMerge: true, select: n.id });
  };

  return (
    <header className="topbar">
      <div className="brand">
        <Logo />
        <span className="brand-name">CopperHound</span>
        {isMockMode && <span className="tag warn">mock data</span>}
      </div>
      <div className="global-search">
        <KindSelect label="Search kind filter" value={kind} onChange={setKind} />
        <NodePicker
          label="Search objects"
          placeholder={kind ? `Search ${kind} objects…` : undefined}
          clearOnSelect
          kind={kind || undefined}
          onSelect={pick}
        />
      </div>
      {health && !health.graph_loaded && <span className="tag warn">no graph loaded</span>}
      <span className="spacer" />
      {busy && <span className="spinner" role="status" aria-label="Working" />}
      {health && <span className="muted small-text">v{health.version}</span>}
      <button
        type="button"
        className="icon-btn"
        onClick={() => update({ theme: theme === "dark" ? "light" : "dark" })}
        aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        title="Toggle theme"
      >
        {theme === "dark" ? "☀" : "☾"}
      </button>
      <UserMenu onLogout={onLogout} />
    </header>
  );
}
