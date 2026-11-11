// Edge kind explanations from GET /edge-kinds (`help`: description / abuse / remediation).

import { useState } from "react";
import type { NodeId } from "../api/types";
import { useCatalog } from "../state/CatalogContext";
import { Derivation } from "./Derivation";

/** Edge kind name with its description as a tooltip; non-traversable kinds are marked. */
export function EdgeKindLabel({ kind, className }: { kind: string; className?: string }) {
  const { edgeKinds, isTraversable } = useCatalog();
  const info = edgeKinds.find((k) => k.name === kind);
  const traversable = isTraversable(kind);
  const title = [info?.help?.description, traversable ? null : "Not traversable: never part of an attack path."].filter(Boolean).join("\n\n");
  return (
    <span className={`edge-kind-label ${info?.help ? "has-help" : ""} ${traversable ? "" : "non-traversable"} ${className ?? ""}`} title={title || undefined}>
      {kind}
    </span>
  );
}

/** Full help for one edge kind. Kinds without curated text show only their category and traversability. */
export function EdgeHelpView({ kind, compact }: { kind: string; compact?: boolean }) {
  const { edgeKinds, isTraversable, edgeCategory } = useCatalog();
  const help = edgeKinds.find((k) => k.name === kind)?.help ?? null;
  const traversable = isTraversable(kind);
  return (
    <div className={`edge-help ${compact ? "compact" : ""}`}>
      <div className="row gap wrap">
        <strong className="edge-kind">{kind}</strong>
        <span className="muted small-text">{edgeCategory(kind)}</span>
        {traversable ? <span className="tag small-tag">traversable</span> : <span className="tag off small-tag">not traversable</span>}
      </div>
      {help ? (
        <dl className="edge-help-fields">
          <dt>What it means</dt>
          <dd>{help.description}</dd>
          <dt>Abuse</dt>
          <dd>{help.abuse}</dd>
          <dt>Remediation</dt>
          <dd>{help.remediation}</dd>
        </dl>
      ) : (
        <p className="muted small-text">
          {traversable
            ? "Collected relationship that grants control of the target; it is followed by path finding and exposure analysis."
            : "Informational relationship; path finding and exposure analysis do not follow it."}
        </p>
      )}
    </div>
  );
}

/** Edge kind that expands to its help on click (used in hop lists). With `edge`, derived kinds also offer their composition. */
export function EdgeKindToggle({ kind, suffix, edge }: { kind: string; suffix?: string; edge?: { src: NodeId; dst: NodeId } }) {
  const [open, setOpen] = useState(false);
  const { isComposite } = useCatalog();
  return (
    <>
      <button type="button" className="link-btn edge-kind-toggle" aria-expanded={open} onClick={() => setOpen(!open)} title="What does this edge mean?">
        <EdgeKindLabel kind={kind} />
        {suffix}
        <span className="muted" aria-hidden="true">
          {" "}
          ⓘ
        </span>
      </button>
      {open && <EdgeHelpView kind={kind} compact />}
      {open && edge && isComposite(kind) && <Derivation src={edge.src} dst={edge.dst} kind={kind} />}
    </>
  );
}

/** Help for each distinct edge kind in a list that has curated text (e.g. a finding's items). */
export function EdgeHelpList({ kinds, title }: { kinds: string[]; title?: string }) {
  const { edgeKinds } = useCatalog();
  const withHelp = [...new Set(kinds)].filter((k) => edgeKinds.find((e) => e.name === k)?.help);
  if (withHelp.length === 0) return null;
  return (
    <div className="edge-help-list">
      {title && <h2>{title}</h2>}
      {withHelp.map((k) => (
        <EdgeHelpView key={k} kind={k} />
      ))}
    </div>
  );
}
