import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import type { Node } from "../../api/types";
import { KindBadge } from "../../components/KindBadge";
import { Modal } from "../../components/Modal";
import { navigate } from "../../hooks/useRoute";
import { useApp } from "../../state/AppContext";
import { useZones } from "../../state/ZonesContext";

const NEW = "__new__";

/** "Add to zone…": put objects into a custom zone by hand, or start a new zone with them. */
export function AddToZoneDialog({ nodes, onClose }: { nodes: Node[]; onClose: () => void }) {
  const { zones, members, reload } = useZones();
  const { notify } = useApp();
  const custom = zones.filter((z) => !z.builtin);
  const [target, setTarget] = useState(custom[0]?.id ?? NEW);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const oids = nodes.map((n) => n.objectid);
  const what = nodes.length === 1 ? nodes[0]!.name : `${nodes.length} objects`;
  /** Already members (when the zone's members are loaded). */
  const inZone = (id: string) => {
    const m = members.get(id);
    return m !== undefined && nodes.every((n) => m.has(n.id));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      if (target === NEW) {
        const z = await api.createZone({ name: name.trim(), selector: "", objects: oids });
        notify(`Created zone “${z.name}” with ${what}.`);
        reload();
        navigate("zones", z.id);
      } else {
        const r = await api.zoneObjects(target, { add: oids });
        notify(r.added > 0 ? `Added ${what} to “${r.zone.name}”.` : `${what} was already added to “${r.zone.name}”.`);
        reload();
      }
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={`Add ${what} to a zone`} onClose={onClose}>
      <form className="form-stack" onSubmit={(e) => void submit(e)}>
        <p className="muted small-text">
          Objects added by hand stay in the zone whatever its selector matches, and count as certified in zone review.
 To put an object in Tier Zero, use Mark Tier Zero instead.
        </p>
        {nodes.length === 1 && (
          <p>
            <KindBadge kind={nodes[0]!.kind} /> <strong>{nodes[0]!.name}</strong>
          </p>
        )}
        <fieldset className="radio-list">
          <legend>Zone</legend>
          {custom.map((z) => (
            <label key={z.id} className="toggle">
              <input type="radio" name="zone" value={z.id} checked={target === z.id} onChange={() => setTarget(z.id)} />
              <span className="zone-swatch" style={{ background: z.color }} /> {z.name}
              <span className="muted small-text"> ({z.member_count.toLocaleString()})</span>
              {inZone(z.id) && <span className="tag">already a member</span>}
            </label>
          ))}
          <label className="toggle">
            <input type="radio" name="zone" value={NEW} checked={target === NEW} onChange={() => setTarget(NEW)} />
            New zone…
          </label>
        </fieldset>
        {target === NEW && (
          <label>
            Name of the new zone
            <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus maxLength={100} />
          </label>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="row gap">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={saving || (target === NEW && !name.trim())}>
            {saving ? "Adding…" : target === NEW ? "Create zone" : "Add to zone"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Zone dialogs opened from anywhere (canvas context menu, details drawer). */
export function ZoneDialogs() {
  const { addToZone, openAddToZone } = useZones();
  return addToZone ? <AddToZoneDialog nodes={addToZone} onClose={() => openAddToZone(null)} /> : null;
}
