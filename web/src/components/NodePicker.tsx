import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { api, errorMessage } from "../api/client";
import type { Node } from "../api/types";
import { useDebounced } from "../hooks/useDebounced";
import { KindBadge } from "./KindBadge";

/**
 * How a result matched, mirroring the server's ranking (exact name / object ID, then
 * name prefix, then name substring), so substring hits are recognisable as such.
 */
function MatchType({ q, node }: { q: string; node: Node }) {
  const query = q.toLowerCase();
  const name = node.name.toLowerCase();
  if (name === query) return null;
  if (node.objectid.toLowerCase() === query) return <span className="match-type">object ID</span>;
  if (name.startsWith(query)) return null;
  if (name.includes(query)) return <span className="match-type">contains</span>;
  return null;
}

interface Props {
  label: string;
  placeholder?: string;
  /** Selected node; when set (and not clearOnSelect) it is shown as a chip. */
  value?: Node | null;
  onSelect: (node: Node) => void;
  onClear?: () => void;
  clearOnSelect?: boolean;
  className?: string;
  /** Restrict results to one node kind. */
  kind?: string;
}

/** Debounced autocomplete over GET /search, keyboard navigable (combobox pattern). */
export function NodePicker({ label, placeholder, value, onSelect, onClear, clearOnSelect, className, kind }: Props) {
  const [text, setText] = useState("");
  const [results, setResults] = useState<Node[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const q = useDebounced(text.trim(), 250);
  const seq = useRef(0);
  const listId = useId();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (q.length < 2) {
      setResults([]);
      setError(null);
      return;
    }
    const mine = ++seq.current;
    api
      .search(q, 12, kind)
      .then((r) => {
        if (mine !== seq.current) return;
        setResults(r);
        setError(null);
        setActive(0);
      })
      .catch((e: unknown) => {
        if (mine === seq.current) setError(errorMessage(e));
      });
  }, [q, kind]);

  const choose = (n: Node) => {
    onSelect(n);
    setOpen(false);
    setText("");
    setResults([]);
    if (clearOnSelect) inputRef.current?.blur();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setOpen(true);
      setActive((a) => Math.min(a + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      const n = results[active];
      if (n) {
        e.preventDefault();
        choose(n);
      }
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  };

  if (value && !clearOnSelect) {
    return (
      <div className={`picker-chip ${className ?? ""}`}>
        <KindBadge kind={value.kind} />
        <span className="picker-chip-name" title={value.name}>
          {value.name}
        </span>
        {onClear && (
          <button type="button" className="icon-btn" aria-label={`Clear ${label}`} onClick={onClear}>
            ×
          </button>
        )}
      </div>
    );
  }

  const showList = open && (results.length > 0 || error !== null || (q.length >= 2 && results.length === 0));

  return (
    <div className={`picker ${className ?? ""}`}>
      <input
        ref={inputRef}
        type="search"
        role="combobox"
        aria-label={label}
        aria-expanded={showList}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={showList && results[active] ? `${listId}-${active}` : undefined}
        placeholder={placeholder ?? "Search by name or object ID…"}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => window.setTimeout(() => setOpen(false), 150)}
        onKeyDown={onKeyDown}
        autoComplete="off"
        spellCheck={false}
      />
      {showList && (
        <ul className="picker-list" id={listId} role="listbox">
          {error && <li className="picker-empty error">{error}</li>}
          {!error && results.length === 0 && <li className="picker-empty muted">No matches</li>}
          {results.map((n, i) => (
            <li
              key={n.id}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              className={i === active ? "active" : ""}
              onMouseDown={(e) => {
                e.preventDefault();
                choose(n);
              }}
              onMouseEnter={() => setActive(i)}
            >
              <KindBadge kind={n.kind} />
              <span className="picker-name">{n.name}</span>
              <MatchType q={q} node={n} />
              {n.tier0 && <span className="tag tier0">T0</span>}
              {n.owned && <span className="tag owned">owned</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
