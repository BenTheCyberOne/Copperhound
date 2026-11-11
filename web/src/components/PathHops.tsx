import type { GraphResult, Hop, Node, NodeId } from "../api/types";
import { useApp } from "../state/AppContext";
import { EdgeKindToggle } from "./EdgeHelp";
import { KindBadge } from "./KindBadge";

/**
 * Hops of path `i` of a result: `hops` (POST /path) or `path_hops` (queries), falling
 * back to matching `paths` against `edges` for servers that predate v1.1.
 */
export function hopsOf(result: GraphResult, i = 0): Hop[] {
  if (i === 0 && result.hops) return result.hops;
  const explicit = result.path_hops?.[i];
  if (explicit) return explicit;
  const path = result.paths?.[i] ?? [];
  return path.slice(1).flatMap((dst, j) => {
    const src = path[j]!;
    const e = result.edges.find((x) => x.src === src && x.dst === dst);
    return e ? [e] : [{ src, dst, kind: "?" }];
  });
}

/** Textual hop list: node → kind → node … */
export function PathHops({ hops, nodes }: { hops: Hop[]; nodes: Node[] }) {
  const { select, store } = useApp();
  if (hops.length === 0) return null;
  const byId = new Map<NodeId, Node>(nodes.map((n) => [n.id, n]));
  const sequence = [hops[0]!.src, ...hops.map((h) => h.dst)];

  return (
    <ol className="hops" aria-label="Path hops">
      {sequence.map((id, i) => {
        const n = byId.get(id);
        const hop = hops[i];
        return (
          <li key={`${id}-${i}`}>
            <button type="button" className="hop-node" disabled={!store.has(id)} onClick={() => select(id)} title="Show details">
              {n ? <KindBadge kind={n.kind} /> : null}
              <span className="ellipsis">{n?.name ?? `#${id}`}</span>
              {n?.tier0 && <span className="tag tier0">T0</span>}
            </button>
            {hop && (
              <div className="hop-edge">
                <EdgeKindToggle kind={hop.kind} suffix=" →" edge={hop.kind === "?" ? undefined : hop} />
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
