import { useEffect, useMemo, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { Direction, NodeDetail } from "../api/types";
import { CATEGORY_ORDER } from "../graph/kinds";
import { useCollapsed } from "../hooks/useCollapsed";
import { useSources } from "../hooks/useSources";
import { when } from "../util/format";
import { collectedSourceHelp, collectedSourceLabel, sourceName } from "../util/sources";
import { useResizableWidth } from "../hooks/useResizableWidth";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";
import { EdgeKindLabel } from "./EdgeHelp";
import { KindBadge } from "./KindBadge";
import { PropertySections } from "./PropertySections";
import { Section } from "./Section";
import { useNodeActions } from "./useNodeActions";

const COLLAPSE_KEY = "copperhound.drawerSections";

function EdgeCounts({ detail, dir, open, onToggle }: { detail: NodeDetail; dir: Direction; open: boolean; onToggle: () => void }) {
  const { expand } = useApp();
  const { edgeCategory } = useCatalog();
  const counts = Object.entries(detail.edge_counts[dir]);
  const total = dir === "out" ? detail.out_degree : detail.in_degree;
  const groups = CATEGORY_ORDER.map((c) => ({
    category: c,
    items: counts.filter(([k]) => edgeCategory(k) === c).sort((a, b) => b[1] - a[1]),
  })).filter((g) => g.items.length > 0);

  return (
    <Section
      title={
        <>
          {dir === "out" ? "Outbound edges" : "Inbound edges"} <span className="muted num">{total}</span>
        </>
      }
      open={open}
      onToggle={onToggle}
      actions={
        total > 0 && (
          <button type="button" className="small" onClick={() => void expand(detail.id, dir)}>
            Load all
          </button>
        )
      }
    >
      {groups.length === 0 && <p className="muted small-text">None</p>}
      {groups.map((g) => (
        <div key={g.category} className="edge-group">
          <div className="edge-group-label">{g.category}</div>
          <ul className="edge-counts">
            {g.items.map(([kind, n]) => (
              <li key={kind}>
                <button
                  type="button"
                  className="edge-count"
                  onClick={() => void expand(detail.id, dir, kind)}
                  title={`Load ${dir === "out" ? "outbound" : "inbound"} ${kind} edges onto the canvas`}
                >
                  <EdgeKindLabel kind={kind} />
                  <span className="num">{n}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </Section>
  );
}

/** `_sources` property: source ids, newest collection first (v1.5). */
function sourceIds(props: Record<string, unknown> | undefined): number[] {
  const v = props?._sources;
  return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
}

/** "Seen in": the input files that describe this node, resolved through /sources. */
function SeenIn({ ids }: { ids: number[] }) {
  const data = useSources(ids.length > 0);
  if (ids.length === 0) return null;
  return (
    <>
      <dt title="Input files that describe this object, newest collection first">Seen in</dt>
      <dd>
        <ol className="seen-in">
          {ids.map((id, i) => {
            const s = data?.sources.find((x) => x.id === id);
            if (!s) {
              return (
                <li key={id} className="muted">
                  source #{id}
                  {data === null ? "" : " (not in the source list)"}
                </li>
              );
            }
            return (
              <li key={id}>
                <span className="break" title={sourceName(s)}>
                  {s.entry ?? s.file}
                </span>
                {s.entry && <div className="muted break">{s.file}</div>}
                <div className="muted">
                  {s.collected_at ? when(s.collected_at) : <span className="warn-text">undated</span>}
                  <span title={collectedSourceHelp(s.collected_at_source)}> · {collectedSourceLabel(s.collected_at_source)}</span>
                  {i === 0 && ids.length > 1 && s.collected_at && <span className="tag ok small-tag">newest</span>}
                </div>
              </li>
            );
          })}
        </ol>
      </dd>
    </>
  );
}

export function DetailsDrawer() {
  const { selectedId, select, marksVersion, store } = useApp();
  const { nodeCategory } = useCatalog();
  const [detail, setDetail] = useState<NodeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const actions = useNodeActions(detail, { includeRemove: true });
  const { isOpen, toggle } = useCollapsed(COLLAPSE_KEY, true, ["props-other"]);
  const panel = useResizableWidth<HTMLElement>({
    storageKey: "copperhound.drawerWidth",
    min: 280,
    reserve: 560,
    edge: "left",
    label: "Resize details panel",
  });

  useEffect(() => {
    if (selectedId === null) {
      setDetail(null);
      return;
    }
    let live = true;
    setError(null);
    api
      .node(selectedId)
      .then((d) => {
        if (!live) return;
        setDetail(d);
        const { id, objectid, name, kind, tier0, owned, enabled } = d;
        store.updateNode({ id, objectid, name, kind, tier0, owned, enabled });
      })
      .catch((e: unknown) => live && setError(errorMessage(e)));
    return () => {
      live = false;
    };
  }, [selectedId, marksVersion, store]);

  const seenIn = useMemo(() => sourceIds(detail?.properties), [detail]);
  // `_sources` is shown resolved under "Seen in", not as a raw property.
  const properties = useMemo(() => {
    if (!detail || !("_sources" in detail.properties)) return detail?.properties ?? {};
    const { _sources: _omit, ...rest } = detail.properties;
    return rest;
  }, [detail]);

  if (selectedId === null) return null;

  const copyId = async () => {
    if (!detail) return;
    try {
      await navigator.clipboard.writeText(detail.objectid);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // clipboard permission denied; the value is still selectable
    }
  };

  return (
    <aside ref={panel.ref} className="drawer" aria-label="Object details" style={panel.style}>
      <div className="drawer-grip" {...panel.gripProps} />
      <div className="drawer-head">
        {detail && <KindBadge kind={detail.kind} />}
        <h2 className="drawer-title" title={detail?.name}>
          {detail?.name ?? (error ? "Error" : "Loading…")}
        </h2>
        <button type="button" className="icon-btn" aria-label="Close details" onClick={() => select(null)}>
          ×
        </button>
      </div>
      {error && <p className="error pad">{error}</p>}
      {detail && detail.id === selectedId && (
        <div className="drawer-body">
          <div className="drawer-actions">
            {actions.map((a) => (
              <button key={a.id} type="button" className={`small ${a.danger ? "danger" : ""}`} onClick={a.run} disabled={a.disabled} title={a.title}>
                {a.label}
              </button>
            ))}
          </div>

          <PropertySections
            properties={properties}
            adcsObject={nodeCategory(detail.kind) === "ADCS"}
            isOpen={isOpen}
            toggle={toggle}
            afterOverview={
              <>
                <EdgeCounts detail={detail} dir="out" open={isOpen("out")} onToggle={() => toggle("out")} />
                <EdgeCounts detail={detail} dir="in" open={isOpen("in")} onToggle={() => toggle("in")} />
              </>
            }
            overviewExtra={
              <dl className="fields">
                <dt>Kind</dt>
                <dd>
                  {detail.kind} <span className="muted small-text">· {nodeCategory(detail.kind)}</span>
                </dd>
                <dt>Object ID</dt>
                <dd>
                  <code className="break">{detail.objectid}</code>
                  <button type="button" className="link-btn" onClick={() => void copyId()}>
                    {copied ? "copied" : "copy"}
                  </button>
                </dd>
                <dt>Status</dt>
                <dd className="tags">
                  <span className={`tag ${detail.enabled ? "ok" : "off"}`}>{detail.enabled ? "enabled" : "disabled"}</span>
                  {detail.tier0 && <span className="tag tier0">Tier Zero</span>}
                  {detail.owned && <span className="tag owned">owned</span>}
                </dd>
                <SeenIn ids={seenIn} />
                {detail.flags.length > 0 && (
                  <>
                    <dt>Flags</dt>
                    <dd className="tags">
                      {detail.flags.map((f) => (
                        <span key={f} className="tag">
                          {f}
                        </span>
                      ))}
                    </dd>
                  </>
                )}
              </dl>
            }
          />
        </div>
      )}
    </aside>
  );
}
