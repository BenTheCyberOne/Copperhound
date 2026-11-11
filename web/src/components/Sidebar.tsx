import { useRef, type KeyboardEvent } from "react";
import { useResizableWidth } from "../hooks/useResizableWidth";
import { useApp, type SidebarTab } from "../state/AppContext";
import { PathTab } from "../tabs/PathTab";
import { QueriesTab } from "../tabs/queries/QueriesTab";
import { Tier0Tab } from "../tabs/Tier0Tab";

const TABS: { id: SidebarTab; label: string }[] = [
  { id: "path", label: "Path" },
  { id: "queries", label: "Queries" },
  { id: "tier0", label: "Exposure" },
];

export function Sidebar() {
  const { tab, setTab } = useApp();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const panel = useResizableWidth<HTMLElement>({
    storageKey: "copperhound.sidebarWidth",
    min: 260,
    reserve: 480,
    edge: "right",
    label: "Resize side panel",
  });

  // Arrow-key navigation per the WAI-ARIA tabs pattern.
  const onKeyDown = (e: KeyboardEvent) => {
    const i = TABS.findIndex((t) => t.id === tab);
    const delta = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    e.preventDefault();
    const next = (i + delta + TABS.length) % TABS.length;
    setTab(TABS[next]!.id);
    tabRefs.current[next]?.focus();
  };

  return (
    <nav ref={panel.ref} className="sidebar" aria-label="Analysis tools" style={panel.style}>
      <div className="sidebar-grip" {...panel.gripProps} />
      <div className="tabs" role="tablist" onKeyDown={onKeyDown}>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            className={tab === t.id ? "active" : ""}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {/* Panels stay mounted so their state survives tab switches. */}
      <div className="tab-panel" role="tabpanel" id="panel-path" aria-labelledby="tab-path" hidden={tab !== "path"}>
        <PathTab />
      </div>
      <div className="tab-panel" role="tabpanel" id="panel-queries" aria-labelledby="tab-queries" hidden={tab !== "queries"}>
        <QueriesTab />
      </div>
      <div className="tab-panel" role="tabpanel" id="panel-tier0" aria-labelledby="tab-tier0" hidden={tab !== "tier0"}>
        <Tier0Tab active={tab === "tier0"} />
      </div>
    </nav>
  );
}
