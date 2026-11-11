// Write-only secret input. The server never returns secrets, only whether one is
// stored (`*_set`), so the user chooses to keep, set/replace or clear it.

export interface SecretEdit {
  mode: "keep" | "set" | "clear";
  text: string;
}

export const KEEP_SECRET: SecretEdit = { mode: "keep", text: "" };

/** Request value: undefined keeps the stored secret, "" clears it, a string replaces it. */
export function secretPayload(e: SecretEdit): string | undefined {
  if (e.mode === "clear") return "";
  if (e.mode === "set" && e.text.trim() !== "") return e.text.trim();
  return undefined;
}

interface Props {
  label: string;
  /** A value is stored on the server. */
  isSet: boolean;
  /** Non-secret hint of the stored value, e.g. a URL with its path elided. */
  hint?: string;
  edit: SecretEdit;
  onChange: (e: SecretEdit) => void;
  /** The value cannot be cleared (e.g. a webhook URL). */
  required?: boolean;
  /** Shown instead of the controls when the value comes from the environment. */
  envNote?: string;
  inputType?: "password" | "url" | "text";
  placeholder?: string;
  help?: string;
}

export function SecretField({ label, isSet, hint, edit, onChange, required, envNote, inputType = "password", placeholder, help }: Props) {
  const id = `secret-${label.replace(/\W+/g, "-").toLowerCase()}`;
  return (
    <div className="secret-field">
      <span className="field-title" id={id}>
        {label}
      </span>
      {envNote ? (
        <span className="muted small-text">
          <span className="tag">env</span> {envNote}
        </span>
      ) : edit.mode === "set" ? (
        <div className="row gap">
          <input
            aria-labelledby={id}
            type={inputType}
            autoComplete="off"
            spellCheck={false}
            value={edit.text}
            placeholder={placeholder}
            onChange={(e) => onChange({ mode: "set", text: e.target.value })}
            autoFocus
          />
          {(isSet || !required) && (
            <button type="button" className="small" onClick={() => onChange({ mode: "keep", text: "" })}>
              Cancel
            </button>
          )}
        </div>
      ) : edit.mode === "clear" ? (
        <div className="row gap">
          <span className="warn-text small-text">Will be cleared when you save.</span>
          <button type="button" className="small" onClick={() => onChange({ mode: "keep", text: "" })}>
            Undo
          </button>
        </div>
      ) : isSet ? (
        <div className="row gap wrap">
          <span className="tag ok">stored</span>
          {hint && <code className="break small-text">{hint}</code>}
          <button type="button" className="small" onClick={() => onChange({ mode: "set", text: "" })}>
            Replace
          </button>
          {!required && (
            <button type="button" className="small danger" onClick={() => onChange({ mode: "clear", text: "" })}>
              Clear
            </button>
          )}
        </div>
      ) : (
        <div className="row gap">
          <span className="muted small-text">not set</span>
          <button type="button" className="small" onClick={() => onChange({ mode: "set", text: "" })}>
            Set
          </button>
        </div>
      )}
      {help && <span className="muted small-text">{help}</span>}
    </div>
  );
}
