/** Local date-time for an ISO timestamp; "—" when missing, the raw text when unparsable. */
export function when(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** Percentage for display: one decimal, two below 1 % (0.22 %), no trailing zeros. */
export function pctText(p: number): string {
  const digits = Math.abs(p) < 1 && p !== 0 ? 2 : 1;
  return `${Number(p.toFixed(digits))}%`;
}
