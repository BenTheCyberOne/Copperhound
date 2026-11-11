import type { Node } from "../api/types";
import { useApp } from "../state/AppContext";
import { useFixList } from "../state/FixListContext";
import { useSession } from "../state/SessionContext";

export interface NodeAction {
  id: string;
  label: string;
  run: () => void;
  danger?: boolean;
  separatorBefore?: boolean;
  /** Shown disabled (with `title` explaining why) instead of hidden. */
  disabled?: boolean;
  title?: string;
}

/** Actions shared by the canvas context menu and the details drawer. */
export function useNodeActions(node: Node | null, opts: { includeRemove: boolean }): NodeAction[] {
  const { expand, setMarks, setPathFrom, setPathTo, setTab, store, select, selectedId, notify } = useApp();
  const fixList = useFixList();
  const { gate } = useSession();
  if (!node) return [];
  const markGate = gate("analyst");
  const inSimulation = fixList.list.nodes.some((n) => n.objectid === node.objectid);
  const actions: NodeAction[] = [
    { id: "out", label: "Expand outbound", run: () => void expand(node.id, "out") },
    { id: "in", label: "Expand inbound", run: () => void expand(node.id, "in") },
    {
      id: "from",
      label: "Set as path start",
      separatorBefore: true,
      run: () => {
        setPathFrom(node);
        setTab("path");
      },
    },
    {
      id: "to",
      label: "Set as path end",
      run: () => {
        setPathTo(node);
        setTab("path");
      },
    },
    {
      id: "owned",
      label: node.owned ? "Unmark owned" : "Mark owned",
      separatorBefore: true,
      run: () => void setMarks(node.id, { owned: !node.owned }),
      ...markGate,
    },
    {
      id: "tier0",
      label: node.tier0 ? "Unmark Tier Zero" : "Mark Tier Zero",
      run: () => void setMarks(node.id, { tier0: !node.tier0 }),
      ...markGate,
    },
  ];
  actions.push({
    id: "simulate",
    label: inSimulation ? "Keep node in simulation" : "Remove node in simulation",
    separatorBefore: true,
    run: () => {
      if (inSimulation) fixList.removeNode(node);
      else {
        fixList.addNode(node);
        notify(`${node.name} will be removed in what-if simulations (Remediation view).`);
      }
    },
  });
  if (opts.includeRemove && store.has(node.id)) {
    actions.push({
      id: "remove",
      label: "Remove from canvas",
      danger: true,
      separatorBefore: true,
      run: () => {
        store.removeNode(node.id);
        if (selectedId === node.id) select(null);
      },
    });
  }
  return actions;
}
