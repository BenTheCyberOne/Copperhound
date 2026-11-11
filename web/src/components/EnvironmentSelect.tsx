// Picker for the environment (AD domain / Entra tenant) to scope to.

import type { Environment } from "../api/types";

export function EnvironmentSelect({ value, onChange, list }: { value: string; onChange: (v: string) => void; list: Environment[] }) {
  if (list.length < 2) return null;
  return (
    <select aria-label="Environment" value={value} onChange={(e) => onChange(e.target.value)} title="Show only findings in one domain or tenant">
      <option value="">All domains and tenants</option>
      {list.map((e) => (
        <option key={e.id} value={e.id}>
          {e.kind === "ad" ? "Domain" : "Tenant"}: {e.name} ({e.objects.toLocaleString()})
        </option>
      ))}
    </select>
  );
}
