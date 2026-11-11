// Edge composition: the collected edges and facts a derived edge was built
// from (GET /edges/composition), fetched on demand and drawn on the canvas.

import { useState } from "react";
import { api, errorMessage } from "../api/client";
import type { EdgeComposition, NodeId } from "../api/types";
import { useApp } from "../state/AppContext";
import { EdgeKindLabel } from "./EdgeHelp";

/** Why a derived edge exists: fetched on demand, drawn on the canvas, with the rule's facts. */
export function Derivation({ src, dst, kind }: { src: NodeId; dst: NodeId; kind: string }) {
  const { loadResult, track } = useApp();
  const [data, setData] = useState<EdgeComposition | null>(null);
  const [error, setError] = useState<string | null>(null);
  const draw = (c: EdgeComposition) => {
    const derived = { src, dst, kind };
    loadResult({ ...c, edges: [...c.edges, derived], paths: [] }, { path: true });
  };
  const show = async () => {
    setError(null);
    try {
      const c = await track(api.edgeComposition(src, dst, kind));
      setData(c);
      draw(c);
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  if (!data) {
    return (
      <div className="derivation">
        <button type="button" className="small" onClick={show} title="Show the collected edges and facts this edge was derived from">
          How was this derived?
        </button>
        {error && <p className="error small-text">{error}</p>}
      </div>
    );
  }
  const names = new Map(data.nodes.map((n) => [n.id, n.name || n.objectid]));
  return (
    <div className="derivation">
      <div className="row gap wrap">
        <strong className="small-text">Derived from</strong>
        <button type="button" className="link-btn small-text" onClick={() => draw(data)}>
          Draw again
        </button>
      </div>
      {!data.complete && (
        <p className="warn-text small-text">
          Some requirements of the rule were not found in the loaded graph; the data may have changed since ingest.
        </p>
      )}
      {data.edges.length > 0 && (
        <ul className="derivation-edges">
          {data.edges.map((e) => (
            <li key={`${e.src}-${e.kind}-${e.dst}`}>
              <span className="ellipsis">{names.get(e.src) ?? e.src}</span>
              <EdgeKindLabel kind={e.kind} className="derivation-kind" />
              <span className="ellipsis">{names.get(e.dst) ?? e.dst}</span>
            </li>
          ))}
        </ul>
      )}
      {data.notes.length > 0 && (
        <ul className="derivation-notes">
          {data.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
