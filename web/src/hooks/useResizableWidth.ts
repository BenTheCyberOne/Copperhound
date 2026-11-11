// Drag / keyboard resizing of a side panel's width, persisted in localStorage.
// `edge` is the side the grip sits on: "right" for a left-hand panel (drag
// right to widen), "left" for a right-hand panel (drag left to widen).

import { useEffect, useReducer, useRef, useState, type CSSProperties, type KeyboardEvent, type PointerEvent as ReactPointerEvent } from "react";
import { readLocal, writeLocal } from "./localStore";

interface Options {
  storageKey: string;
  min: number;
  /** Room always left for the rest of the window (canvas, other panels). */
  reserve: number;
  /** Hard upper bound. */
  max?: number;
  edge: "left" | "right";
  label: string;
}

export function useResizableWidth<T extends HTMLElement>({ storageKey, min, reserve, max = 1200, edge, label }: Options) {
  const ref = useRef<T>(null);
  // null = default width from CSS (narrower on small screens).
  const [width, setWidth] = useState<number | null>(() => readLocal<number | null>(storageKey, null));
  const [, rerender] = useReducer((n: number) => n + 1, 0);
  useEffect(() => {
    window.addEventListener("resize", rerender);
    return () => window.removeEventListener("resize", rerender);
  }, []);
  const maxWidth = Math.max(min, Math.min(max, window.innerWidth - reserve));
  const clamp = (w: number) => Math.round(Math.min(maxWidth, Math.max(min, w)));
  const sign = edge === "right" ? 1 : -1;
  const current = () => ref.current?.getBoundingClientRect().width ?? min;
  const save = (w: number | null) => {
    setWidth(w);
    writeLocal(storageKey, w);
  };

  const onPointerDown = (e: ReactPointerEvent) => {
    if (e.button !== 0) return;
    e.preventDefault();
    const startX = e.clientX;
    const startW = current();
    let w = startW;
    document.body.classList.add("col-resizing");
    const move = (ev: PointerEvent) => {
      w = clamp(startW + sign * (ev.clientX - startX));
      setWidth(w);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      document.body.classList.remove("col-resizing");
      writeLocal(storageKey, w);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const onKeyDown = (e: KeyboardEvent) => {
    const step = (e.shiftKey ? 80 : 20) * sign;
    if (e.key === "ArrowRight") save(clamp(current() + step));
    else if (e.key === "ArrowLeft") save(clamp(current() - step));
    else if (e.key === "Home") save(null);
    else return;
    e.preventDefault();
  };

  const style: CSSProperties | undefined = width === null ? undefined : { width: Math.min(width, maxWidth) };
  const gripProps = {
    role: "separator" as const,
    "aria-orientation": "vertical" as const,
    "aria-label": label,
    "aria-valuemin": min,
    "aria-valuemax": maxWidth,
    "aria-valuenow": width ?? undefined,
    tabIndex: 0,
    title: "Drag to resize · double-click to reset",
    onPointerDown,
    onDoubleClick: () => save(null),
    onKeyDown,
  };
  return { ref, style, gripProps };
}
