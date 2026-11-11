// Panel under the canvas holding the canvas nodes table and the tabular query
// result. One shared, resizable height; tabs when both are open, so neither
// pushes the other out of the column.

import { useEffect, useRef, useState } from "react";
import { CanvasTable } from "../graph/CanvasTable";
import { readLocal, writeLocal } from "../hooks/localStore";
import { useApp } from "../state/AppContext";
import { ResultTable } from "./ResultTable";

const HEIGHT_KEY = "copperhound.dockHeight";
const MIN_H = 120;
/** Canvas height always left free above the dock. */
const CANVAS_MIN = 200;

type Tab = "nodes" | "result";

export function BottomDock({ nodesOpen, onCloseNodes }: { nodesOpen: boolean; onCloseNodes: () => void }) {
  const { table, setTable } = useApp();
  const [tab, setTab] = useState<Tab>("result");
  const [height, setHeight] = useState(() => readLocal(HEIGHT_KEY, 280));
  const ref = useRef<HTMLDivElement>(null);

  // Whatever was opened most recently comes to the front.
  useEffect(() => {
    if (table) setTab("result");
  }, [table]);
  useEffect(() => {
    if (nodesOpen) setTab("nodes");
  }, [nodesOpen]);

  if (!table && !nodesOpen) return null;
  const both = table !== null && nodesOpen;
  const current: Tab = !table ? "nodes" : !nodesOpen ? "result" : tab;

  const startResize = (e: React.PointerEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startH = height;
    const column = ref.current?.parentElement?.clientHeight ?? 800;
    const limit = Math.max(MIN_H, column - CANVAS_MIN);
    let h = startH;
    const move = (ev: PointerEvent) => {
      h = Math.min(limit, Math.max(MIN_H, startH + startY - ev.clientY));
      setHeight(h);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      writeLocal(HEIGHT_KEY, h);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const tabs = both ? (
    <div className="dock-tabs" role="tablist" aria-label="Bottom panel">
      <button type="button" role="tab" aria-selected={current === "nodes"} onClick={() => setTab("nodes")}>
        Canvas nodes
      </button>
      <button type="button" role="tab" aria-selected={current === "result"} onClick={() => setTab("result")} title={table.title}>
        Query result
      </button>
    </div>
  ) : undefined;

  return (
    <div ref={ref} className="bottom-dock" style={{ height }}>
      <div className="dock-grip" role="separator" aria-orientation="horizontal" aria-label="Resize panel" onPointerDown={startResize} />
      {/* Both stay mounted so switching tabs keeps filters, sort and scroll. */}
      {nodesOpen && (
        <div className="dock-pane" hidden={current !== "nodes"}>
          <CanvasTable tabs={tabs} onClose={onCloseNodes} />
        </div>
      )}
      {table && (
        <div className="dock-pane" hidden={current !== "result"}>
          <ResultTable table={table} tabs={tabs} onClose={() => setTable(null)} />
        </div>
      )}
    </div>
  );
}
