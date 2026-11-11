import { useState, type KeyboardEvent } from "react";

interface Props {
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
  /** Returns an error message for a value that should not be added. */
  validate?: (v: string) => string | null;
}

/**
 * Editable list of short strings shown as removable chips. Enter or comma adds the
 * typed value; pasted comma/semicolon/newline separated lists are split.
 */
export function ListEditor({ label, values, onChange, placeholder, disabled, validate }: Props) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const add = (raw: string) => {
    const items = raw
      .split(/[,;\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (items.length === 0) return;
    for (const it of items) {
      const err = validate?.(it) ?? null;
      if (err) {
        setError(err);
        return;
      }
    }
    const lower = new Set(values.map((v) => v.toLowerCase()));
    onChange([...values, ...items.filter((it) => !lower.has(it.toLowerCase()))]);
    setText("");
    setError(null);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      add(text);
    } else if (e.key === "Backspace" && !text && values.length > 0) {
      onChange(values.slice(0, -1));
    }
  };

  return (
    <div className={`list-editor ${disabled ? "is-disabled" : ""}`}>
      <ul className="list-chips" aria-label={label}>
        {values.map((v) => (
          <li key={v} className="chip list-chip">
            <span>{v}</span>
            {!disabled && (
              <button type="button" className="icon-btn" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))}>
                ×
              </button>
            )}
          </li>
        ))}
        {values.length === 0 && disabled && <li className="muted small-text">none</li>}
      </ul>
      {!disabled && (
        <div className="row gap">
          <input
            aria-label={`Add to ${label}`}
            value={text}
            placeholder={placeholder}
            onChange={(e) => {
              setText(e.target.value);
              setError(null);
            }}
            onKeyDown={onKeyDown}
            onBlur={() => text.trim() && add(text)}
            spellCheck={false}
          />
          <button type="button" className="small" onClick={() => add(text)} disabled={!text.trim()}>
            Add
          </button>
        </div>
      )}
      {error && <span className="warn-text small-text">{error}</span>}
    </div>
  );
}
