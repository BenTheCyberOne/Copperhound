import { useZones } from "../state/ZonesContext";

/** Zone dropdown (built-in Tier Zero first). */
export function ZoneSelect({ value, onChange, id, label = "Zone" }: { value: string; onChange: (id: string) => void; id?: string; label?: string }) {
  const { zones } = useZones();
  const list = zones.length > 0 ? zones : [{ id: "tier0", name: "Tier Zero", member_count: 0, builtin: true }];
  return (
    <select id={id} aria-label={id ? undefined : label} value={value} onChange={(e) => onChange(e.target.value)}>
      {list.map((z) => (
        <option key={z.id} value={z.id}>
          {z.name}
          {z.member_count ? ` (${z.member_count.toLocaleString()})` : ""}
        </option>
      ))}
    </select>
  );
}
