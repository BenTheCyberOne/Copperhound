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

/** `url` if it is an http(s) link, else undefined: never render a
 *  `javascript:` (or other scheme) URL that came from the server as a link. */
export function webHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}
