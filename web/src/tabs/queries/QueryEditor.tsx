import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { NumberField } from "../../components/NumberField";
import { hopsOf, PathHops } from "../../components/PathHops";
import { useCatalog } from "../../state/CatalogContext";
import { useSession } from "../../state/SessionContext";
import { SYNTAX_SUMMARY, tokenize } from "./chqlHighlight";
import type { QueryFailure, useQueryRunner } from "./useQueryRunner";

const MAX_LISTED_PATHS = 10;

/** Condensed CHQL reference; the full grammar is docs/CHQL.md in the CopperHound repository. */
function SyntaxHelp() {
  return (
    <div className="syntax-help">
      {SYNTAX_SUMMARY.map((s) => (
        <div key={s.title}>
          <div className="edge-group-label">{s.title}</div>
          <pre className="code-block">{s.lines.join("\n")}</pre>
        </div>
      ))}
      <p className="muted small-text">
        A read-only Cypher dialect; most BloodHound queries run unchanged. Full reference, functions, limits and the Cypher
        compatibility table: <code>docs/CHQL.md</code> in the CopperHound repository (also <code>docs/API.md</code> → CHQL).
        Syntax errors underline the reported position.
      </p>
    </div>
  );
}

/** The API reports byte offsets (UTF-8); textarea selection works in UTF-16 code units. */
function byteOffsetToIndex(text: string, byteOffset: number): number {
  const bytes = new TextEncoder().encode(text);
  return new TextDecoder().decode(bytes.slice(0, Math.min(byteOffset, bytes.length))).length;
}

export function ErrorExcerpt({ query, message, position }: { query: string; message: string; position: number | null }) {
  if (position === null) return <p className="error">{message}</p>;
  const index = byteOffsetToIndex(query, position);
  const lineStart = query.lastIndexOf("\n", index - 1) + 1;
  const lineEndRaw = query.indexOf("\n", index);
  const line = query.slice(lineStart, lineEndRaw === -1 ? undefined : lineEndRaw);
  const lineNo = query.slice(0, lineStart).split("\n").length;
  const col = index - lineStart;
  return (
    <div className="error query-error" role="alert">
      <div>
        {message} <span className="muted">(line {lineNo}, column {col + 1})</span>
      </div>
      <pre className="caret">
        {line}
        {"\n"}
        {" ".repeat(col)}^
      </pre>
    </div>
  );
}

function FailureView({ failure, query }: { failure: QueryFailure; query: string }) {
  switch (failure.kind) {
    case "syntax":
    case "semantic":
      return (
        <div>
          <span className={`tag code-${failure.kind}`}>{failure.kind === "syntax" ? "Syntax error" : "Semantic error"}</span>
          <ErrorExcerpt query={query} message={failure.message} position={failure.position} />
        </div>
      );
    case "timeout":
      return (
        <p className="notice warn" role="alert">
          <span>
            <strong>Timed out.</strong> {failure.message} Raise the timeout in Settings → Behaviour or narrow the query.
          </span>
        </p>
      );
    case "cancelled":
      return (
        <p className="notice" role="status">
          <span>
            <strong>Cancelled.</strong> The query was stopped.
          </span>
        </p>
      );
    case "other":
      return <p className="error">{failure.message}</p>;
  }
}

interface Props {
  text: string;
  setText: (t: string) => void;
  limit: number;
  setLimit: (n: number) => void;
  runner: ReturnType<typeof useQueryRunner>;
  onRun: () => void;
  onSave: () => void;
}

export function QueryEditor({ text, setText, limit, setLimit, runner, onRun, onSave }: Props) {
  const saveGate = useSession().gate("analyst");
  const editor = useRef<HTMLTextAreaElement>(null);
  const overlay = useRef<HTMLPreElement>(null);
  const [showHelp, setShowHelp] = useState(false);
  const { health } = useCatalog();
  const { failure, running, summary, result } = runner;

  // Put the caret on the reported error position.
  useEffect(() => {
    if (!failure || !("position" in failure) || failure.position === null) return;
    const index = byteOffsetToIndex(text, failure.position);
    editor.current?.focus();
    editor.current?.setSelectionRange(index, Math.min(index + 1, text.length));
    // Only when a new failure arrives, not on every edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [failure]);

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      onRun();
    }
  };

  const pathCount = result?.paths?.length ?? 0;

  // Syntax colouring drawn behind the transparent textarea; the error position is underlined.
  const errorIndex = failure && "position" in failure && failure.position !== null ? byteOffsetToIndex(text, failure.position) : null;
  const highlighted = useMemo(() => {
    const tokens = tokenize(text);
    return tokens.flatMap((t) => {
      const end = t.start + t.text.length;
      if (errorIndex === null || errorIndex < t.start || errorIndex >= end) {
        return [
          <span key={t.start} className={`tok-${t.cls}`}>
            {t.text}
          </span>,
        ];
      }
      // Split the token around the error character.
      const at = errorIndex - t.start;
      return [
        <span key={`${t.start}a`} className={`tok-${t.cls}`}>
          {t.text.slice(0, at)}
        </span>,
        <span key={`${t.start}b`} className={`tok-${t.cls} tok-error`}>
          {t.text.slice(at, at + 1)}
        </span>,
        <span key={`${t.start}c`} className={`tok-${t.cls}`}>
          {t.text.slice(at + 1)}
        </span>,
      ];
    }).concat(
      errorIndex !== null && errorIndex >= text.length
        ? [
            <span key="eof" className="tok-error tok-eof">
              {" "}
            </span>,
          ]
        : [],
    );
  }, [text, errorIndex]);

  return (
    <section>
      <div className="section-head">
        <h3>CHQL</h3>
        <button type="button" className="link-btn" aria-expanded={showHelp} onClick={() => setShowHelp(!showHelp)}>
          {showHelp ? "Hide syntax" : "Syntax help"}
        </button>
      </div>
      {showHelp && <SyntaxHelp />}
      <div className="chql-wrap">
        <pre ref={overlay} className="chql-highlight" aria-hidden="true">
          {highlighted}
          {"\n"}
        </pre>
        <textarea
          ref={editor}
          className="chql-editor"
          aria-label="CHQL query"
          aria-invalid={errorIndex !== null}
          spellCheck={false}
          rows={5}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            runner.clearFailure();
          }}
          onScroll={(e) => {
            if (overlay.current) {
              overlay.current.scrollTop = e.currentTarget.scrollTop;
              overlay.current.scrollLeft = e.currentTarget.scrollLeft;
            }
          }}
          onKeyDown={onKeyDown}
        />
      </div>
      <div className="row gap wrap">
        {running ? (
          <button type="button" className="danger" onClick={() => void runner.cancel()}>
            Cancel
          </button>
        ) : (
          <button type="button" className="primary" onClick={onRun} disabled={!text.trim()}>
            Run
          </button>
        )}
        <button type="button" onClick={onSave} disabled={!text.trim() || saveGate.disabled} title={saveGate.title ?? "Save to My queries"}>
          Save…
        </button>
        <span className="muted small-text">{running ? "Running…" : "Ctrl+Enter"}</span>
        <span className="spacer" />
        <label className="inline-field">
          Limit
          <NumberField min={1} max={health?.limits.max_query_limit ?? 100000} value={limit} onCommit={setLimit} />
        </label>
      </div>
      {failure && <FailureView failure={failure} query={text} />}
      {summary && <p className="muted">{summary}</p>}
      {result && pathCount > 0 && (
        <details className="query-paths">
          <summary>
            Path hops <span className="muted num">{Math.min(pathCount, MAX_LISTED_PATHS)}</span>
            {pathCount > MAX_LISTED_PATHS && <span className="muted small-text"> of {pathCount}</span>}
          </summary>
          {Array.from({ length: Math.min(pathCount, MAX_LISTED_PATHS) }, (_, i) => (
            <div key={i} className="query-path">
              <div className="muted small-text">Path {i + 1}</div>
              <PathHops hops={hopsOf(result, i)} nodes={result.nodes} />
            </div>
          ))}
        </details>
      )}
    </section>
  );
}
