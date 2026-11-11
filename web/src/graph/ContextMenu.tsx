import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import type { NodeAction } from "../components/useNodeActions";

interface Props {
  title: string;
  actions: NodeAction[];
  x: number;
  y: number;
  onClose: () => void;
}

/** Keyboard-navigable context menu positioned inside the canvas. */
export function ContextMenu({ title, actions, x, y, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });

  // Keep the menu inside the canvas area.
  useLayoutEffect(() => {
    const el = ref.current;
    const parent = el?.offsetParent as HTMLElement | null;
    if (!el || !parent) return;
    setPos({
      left: Math.min(x, parent.clientWidth - el.offsetWidth - 8),
      top: Math.min(y, parent.clientHeight - el.offsetHeight - 8),
    });
  }, [x, y]);

  useEffect(() => {
    ref.current?.querySelector<HTMLButtonElement>("button")?.focus();
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as globalThis.Node)) onClose();
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [onClose]);

  const onKeyDown = (e: KeyboardEvent) => {
    const items = [...(ref.current?.querySelectorAll<HTMLButtonElement>("button") ?? [])];
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      items[(i + 1) % items.length]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      items[(i - 1 + items.length) % items.length]?.focus();
    }
  };

  return (
    <div ref={ref} className="context-menu" role="menu" aria-label={`Actions for ${title}`} style={pos} onKeyDown={onKeyDown}>
      <div className="context-menu-title" title={title}>
        {title}
      </div>
      {actions.map((a) => (
        <button
          key={a.id}
          type="button"
          role="menuitem"
          className={`${a.danger ? "danger" : ""} ${a.separatorBefore ? "sep" : ""}`}
          disabled={a.disabled}
          title={a.title}
          onClick={() => {
            a.run();
            onClose();
          }}
        >
          {a.label}
        </button>
      ))}
    </div>
  );
}
