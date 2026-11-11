import { useState, type FormEvent } from "react";
import { ApiError, api, errorMessage } from "../../api/client";
import type { Zone } from "../../api/types";
import { Modal } from "../../components/Modal";
import { ErrorExcerpt } from "../../tabs/queries/QueryEditor";

interface Props {
  editing: Zone | null;
  onClose: () => void;
  onSaved: (z: Zone) => void;
}

/** Create / edit a custom zone; the server parses and runs the selector on save. */
export function ZoneDialog({ editing, onClose, onSaved }: Props) {
  const [name, setName] = useState(editing?.name ?? "");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [color, setColor] = useState(editing?.color ?? "#a78bfa");
  const [selector, setSelector] = useState(editing?.selector ?? "MATCH (n:Computer) WHERE n.name STARTS WITH 'SRV' RETURN n");
  const [error, setError] = useState<{ message: string; position: number | null } | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    const body = { name: name.trim(), description: description.trim(), selector, color };
    try {
      onSaved(editing ? await api.updateZone(editing.id, body) : await api.createZone(body));
    } catch (err) {
      setError({ message: errorMessage(err), position: err instanceof ApiError ? err.position : null });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={editing ? `Edit zone “${editing.name}”` : "New zone"} onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </label>
        <label>
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label className="color-field">
          Colour on the canvas
          <span className="row gap">
            <input type="color" value={color} onChange={(e) => setColor(e.target.value)} aria-label="Zone colour" />
            <code>{color}</code>
          </span>
        </label>
        <label>
          Selector (CHQL; the nodes it returns are the members)
          <textarea className="chql-editor" rows={4} value={selector} onChange={(e) => setSelector(e.target.value)} spellCheck={false} required />
        </label>
        {error && <ErrorExcerpt query={selector} message={error.message} position={error.position} />}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving || !name.trim() || !selector.trim()}>
            {saving ? "Validating…" : "Save zone"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
