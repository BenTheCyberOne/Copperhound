import { useState, type FormEvent } from "react";
import { ApiError, api, errorMessage } from "../../api/client";
import type { SavedQuery } from "../../api/types";
import { Modal } from "../../components/Modal";
import { ErrorExcerpt } from "./QueryEditor";

interface Props {
  /** Existing query to edit, or null to create one from `initialQuery`. */
  editing: SavedQuery | null;
  initialQuery: string;
  categories: string[];
  onClose: () => void;
  onSaved: (q: SavedQuery) => void;
}

export function SaveQueryDialog({ editing, initialQuery, categories, onClose, onSaved }: Props) {
  const [name, setName] = useState(editing?.name ?? "");
  const [category, setCategory] = useState(editing?.category ?? "Custom");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [query, setQuery] = useState(editing?.query ?? initialQuery);
  const [error, setError] = useState<{ message: string; position: number | null } | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    const body = { name: name.trim(), category: category.trim() || undefined, description: description.trim(), query };
    try {
      const saved = editing ? await api.updateSavedQuery(editing.id, body) : await api.createSavedQuery(body);
      onSaved(saved);
    } catch (err) {
      setError({ message: errorMessage(err), position: err instanceof ApiError ? err.position : null });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={editing ? "Edit saved query" : "Save query"} onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </label>
        <label>
          Category
          <input value={category} onChange={(e) => setCategory(e.target.value)} list="saved-query-categories" />
          <datalist id="saved-query-categories">
            {categories.map((c) => (
              <option key={c} value={c} />
            ))}
          </datalist>
        </label>
        <label>
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label>
          Query
          <textarea className="chql-editor" rows={5} value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} required />
        </label>
        {error && <ErrorExcerpt query={query} message={error.message} position={error.position} />}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving || !name.trim() || !query.trim()}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
