import { useEffect, useState } from "react";

interface Props {
  id?: string;
  value: number;
  min: number;
  max: number;
  step?: number;
  onCommit: (value: number) => void;
}

/** Number input that lets you type freely and clamps on blur / Enter. */
export function NumberField({ id, value, min, max, step, onCommit }: Props) {
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);
  const commit = () => {
    const n = Number(text);
    const v = Number.isFinite(n) && text.trim() !== "" ? Math.min(max, Math.max(min, n)) : value;
    setText(String(v));
    if (v !== value) onCommit(v);
  };
  return (
    <input
      id={id}
      type="number"
      min={min}
      max={max}
      step={step}
      value={text}
      onChange={(e) => setText(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") commit();
      }}
    />
  );
}
