import { useState, type FormEvent } from "react";
import { ApiError, api, errorMessage } from "../../api/client";
import type { Zone } from "../../api/types";
import { Modal } from "../../components/Modal";
import { NumberField } from "../../components/NumberField";
import { ErrorExcerpt } from "../../tabs/queries/QueryEditor";

/** Starting points for common zones. The OT ones use the `purdue_level` and
 *  `ot_role` properties of docs/OT.md, set by an OpenGraph asset inventory. */
const TEMPLATES: { name: string; description: string; selector: string }[] = [
  {
    name: "OT assets (Purdue 0-3)",
    description: "Control systems below the OT DMZ",
    selector: "MATCH (n) WHERE n.purdue_level <= 3 RETURN n",
  },
  {
    name: "Controllers (Purdue 0-1)",
    description: "PLCs, safety systems, RTUs and field devices",
    selector: "MATCH (n) WHERE n.purdue_level <= 1 RETURN n",
  },
  {
    name: "Engineering workstations",
    description: "Hosts that can program controllers",
    selector: "MATCH (n) WHERE n.ot_role = 'EWS' RETURN n",
  },
  {
    name: "OT DMZ (Purdue 3.5)",
    description: "Jump hosts, historian replicas and patch servers between IT and OT",
    selector: "MATCH (n) WHERE n.purdue_level = 3.5 RETURN n",
  },
  {
    name: "OT organizational unit",
    description: "Everything under the OT OU (edit the distinguished name)",
    selector: "MATCH (n) WHERE n.distinguishedname ENDS WITH ',OU=PLANT,DC=CORP,DC=LOCAL' RETURN n",
  },
  {
    name: "OT domain",
    description: "Every object of a separate OT domain (edit the domain name)",
    selector: "MATCH (n) WHERE n.domain = 'OT.CORP.LOCAL' RETURN n",
  },
];

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
  const [weight, setWeight] = useState(editing?.weight ?? 1);
  const byHand = editing?.objects.length ?? 0;
  const [error, setError] = useState<{ message: string; position: number | null } | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    const body = { name: name.trim(), description: description.trim(), selector, color, weight };
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
        {!editing && (
          <label>
            Start from a template
            <select
              value=""
              onChange={(e) => {
                const t = TEMPLATES[Number(e.target.value)];
                if (!t) return;
                setName(t.name);
                setDescription(t.description);
                setSelector(t.selector);
                setError(null);
              }}
            >
              <option value="">Choose…</option>
              {TEMPLATES.map((t, i) => (
                <option key={t.name} value={i}>
                  {t.name}
                </option>
              ))}
            </select>
          </label>
        )}
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
          Weight in cross-zone plans (0-100; 0 leaves the zone out)
          <NumberField value={weight} min={0} max={100} onCommit={(v) => setWeight(Math.round(v))} />
        </label>
        <label>
          Selector (CHQL; the nodes it returns are the members{byHand > 0 ? `, plus ${byHand} added by hand; may be empty` : ""})
          <textarea className="chql-editor" rows={4} value={selector} onChange={(e) => setSelector(e.target.value)} spellCheck={false} required={byHand === 0} />
        </label>
        {error && <ErrorExcerpt query={selector} message={error.message} position={error.position} />}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving || !name.trim() || (!selector.trim() && byHand === 0)}>
            {saving ? "Validating…" : "Save zone"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
