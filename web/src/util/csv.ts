/** Formats a value for display / CSV: objects as JSON, null/undefined as empty. */
export function cellText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function csvEscape(s: string): string {
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Downloads rows as an RFC 4180 CSV file. */
export function downloadCsv(name: string, header: string[], rows: unknown[][]): void {
  const lines = [header, ...rows].map((r) => r.map((v) => csvEscape(cellText(v))).join(","));
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([`${lines.join("\r\n")}\r\n`], { type: "text/csv;charset=utf-8" }));
  a.download = name;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
