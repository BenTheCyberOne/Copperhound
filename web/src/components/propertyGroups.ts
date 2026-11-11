// Groups raw collector properties into the sections shown in the details drawer.

export type SectionId = "overview" | "security" | "time" | "adcs" | "other";

export const SECTIONS: { id: SectionId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "security", label: "Security flags" },
  { id: "time", label: "Timestamps" },
  { id: "adcs", label: "Certificate services" },
  { id: "other", label: "Other properties" },
];

const OVERVIEW = new Set([
  "name",
  "objectid",
  "domain",
  "domainsid",
  "tenantid",
  "displayname",
  "description",
  "distinguishedname",
  "samaccountname",
  "userprincipalname",
  "email",
  "title",
  "operatingsystem",
  "dnshostname",
]);

const SECURITY =
  /^(enabled|admincount|hasspn|dontreqpreauth|unconstraineddelegation|trustedtoauth|allowedtodelegate|sensitive|pwdneverexpires|passwordnotreqd|highvalue|haslaps|serviceprincipalnames|sidhistory|isaclprotected|blocksinheritance|onpremsyncenabled|isassignabletorole|smartcardrequired|unconstrained.*|constrained.*|.*delegat.*|protected.*|.*encryption.*)$/i;

export const TIME_KEY = /(time|date|lastlogon|pwdlastset|whencreated|whenchanged|expir|lastset|created_at|updated_at)/i;

const ADCS_KEYS =
  /(cert|template|eku|enroll|^caname$|schema|issuance|oid|subject|^san|manager|authorizedsignatures|validity|renewal|ca(security|type)|thumbprint|publishedto)/i;

/** `adcsObject`: the node belongs to the ADCS category (certificate-specific keys get their own section). */
export function sectionOf(key: string, adcsObject: boolean): SectionId {
  const k = key.toLowerCase();
  if (OVERVIEW.has(k)) return "overview";
  if (SECURITY.test(k)) return "security";
  if (TIME_KEY.test(k)) return "time";
  if (adcsObject && ADCS_KEYS.test(k)) return "adcs";
  return "other";
}

/** Interprets epoch seconds / milliseconds / ISO strings; null for "never" or unparsable. */
export function asDate(v: unknown): Date | null {
  if (typeof v === "number") {
    if (v <= 0) return null;
    if (v > 1e8 && v < 1e11) return new Date(v * 1000);
    if (v >= 1e11 && v < 1e14) return new Date(v);
    return null;
  }
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v)) {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 86400],
  ["month", 30 * 86400],
  ["week", 7 * 86400],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
];

export function relativeAge(d: Date, now = Date.now()): string {
  const secs = (d.getTime() - now) / 1000;
  for (const [unit, size] of UNITS) {
    if (Math.abs(secs) >= size) return rtf.format(Math.round(secs / size), unit);
  }
  return rtf.format(Math.round(secs), "second");
}
