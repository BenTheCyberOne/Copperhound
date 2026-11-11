import { CATEGORY_ORDER } from "../graph/kinds";
import { useCatalog } from "../state/CatalogContext";

interface Props {
  value: string;
  onChange: (kind: string) => void;
  label: string;
}

/** Node-kind dropdown grouped by category; only kinds present in the graph are offered. */
export function KindSelect({ value, onChange, label }: Props) {
  const { nodeKinds } = useCatalog();
  const present = nodeKinds.filter((k) => k.count > 0);
  return (
    <select className="kind-select" aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">All kinds</option>
      {CATEGORY_ORDER.map((c) => {
        const kinds = present.filter((k) => k.category === c).sort((a, b) => a.name.localeCompare(b.name));
        if (kinds.length === 0) return null;
        return (
          <optgroup key={c} label={c}>
            {kinds.map((k) => (
              <option key={k.name} value={k.name}>
                {k.name} ({k.count.toLocaleString()})
              </option>
            ))}
          </optgroup>
        );
      })}
    </select>
  );
}
