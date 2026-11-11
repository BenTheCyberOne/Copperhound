// Minimal hash router so every view is deep-linkable, e.g. #/findings/dcsync-non-tier0
// or #/posture?from=snap-0001&to=snap-0009.

import { useEffect, useState } from "react";

export const VIEWS = ["explore", "filter", "findings", "remediation", "posture", "zones", "alerts", "data", "reports", "account", "admin"] as const;
export type View = (typeof VIEWS)[number];

export interface Route {
  view: View;
  /** Second path segment, e.g. a finding or zone id. */
  id: string | null;
  params: URLSearchParams;
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#\/?/, "");
  const [path = "", query = ""] = raw.split("?");
  const [first, second] = path.split("/").map((s) => decodeURIComponent(s));
  const view = (VIEWS as readonly string[]).includes(first ?? "") ? (first as View) : "explore";
  return { view, id: view === first && second ? second : null, params: new URLSearchParams(query) };
}

export function routeHref(view: View, id?: string | null, params?: Record<string, string>): string {
  const qs = params ? new URLSearchParams(params).toString() : "";
  return `#/${view}${id ? `/${encodeURIComponent(id)}` : ""}${qs ? `?${qs}` : ""}`;
}

export function navigate(view: View, id?: string | null, params?: Record<string, string>): void {
  const href = routeHref(view, id, params);
  if (window.location.hash !== href) window.location.hash = href;
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
