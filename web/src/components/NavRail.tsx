import type { ReactNode } from "react";
import type { Role } from "../api/types";
import { routeHref, type Route, type View } from "../hooks/useRoute";
import { useApp } from "../state/AppContext";
import { useFixList } from "../state/FixListContext";
import { useSession } from "../state/SessionContext";

type IconName = View | "settings" | "users" | "audit" | "server" | "sso" | "notifications" | "collectors";

const ICONS: Record<IconName, ReactNode> = {
  reports: (
    <>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M15 3v4h4M9 12h7M9 16h7M9 8h3" />
    </>
  ),
  account: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21c1-4.5 4.3-6.5 8-6.5s7 2 8 6.5" />
    </>
  ),
  admin: (
    <>
      <path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.2" />
      <path d="M3 20c.8-3.6 3.2-5.3 6-5.3s5.2 1.7 6 5.3" />
      <circle cx="17" cy="9" r="2.5" />
      <path d="M16 14.5c2.6.2 4.3 1.8 5 4.5" />
    </>
  ),
  audit: (
    <>
      <path d="M5 4h14v16H5z" />
      <path d="M8 8h8M8 12h8M8 16h5" />
    </>
  ),
  server: (
    <>
      <rect x="4" y="4" width="16" height="6" rx="1.5" />
      <rect x="4" y="14" width="16" height="6" rx="1.5" />
      <path d="M8 7h.01M8 17h.01" />
    </>
  ),
  filter: (
    <>
      <path d="M4 5h16l-6 7.5V19l-4 1.5v-8z" />
    </>
  ),
  alerts: (
    <>
      <path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z" />
      <path d="M10 20.5a2.2 2.2 0 0 0 4 0" />
    </>
  ),
  sso: (
    <>
      <circle cx="8" cy="12" r="3.5" />
      <path d="M11.5 12H21M17 12v3M20 12v2" />
    </>
  ),
  collectors: (
    <>
      <rect x="4" y="13" width="16" height="7" rx="1.5" />
      <path d="M8 16.5h.01M12 10V3M9 6l3-3 3 3" />
    </>
  ),
  notifications: (
    <>
      <path d="M4 6h16v10H9l-4 3.5V16H4z" />
      <path d="M8 10h8M8 13h5" />
    </>
  ),
  explore: (
    <>
      <circle cx="6" cy="7" r="2.2" />
      <circle cx="18" cy="6" r="2.2" />
      <circle cx="12" cy="17" r="2.2" />
      <path d="M8 7.5l8-1M7 9l4 6M17 8l-4 7" />
    </>
  ),
  findings: (
    <>
      <path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z" />
      <path d="M12 8v5M12 16v.5" />
    </>
  ),
  remediation: (
    <>
      <path d="M4 20l7-7" />
      <path d="M14.5 4.5a4 4 0 0 0 5 5L17 12l-5-5z" />
      <path d="M9 11l4 4" />
    </>
  ),
  posture: (
    <>
      <path d="M4 20V4M4 20h16" />
      <path d="M7 15l4-4 3 3 5-6" />
    </>
  ),
  zones: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4.5" />
      <circle cx="12" cy="12" r="1.2" />
    </>
  ),
  data: (
    <>
      <ellipse cx="12" cy="6" rx="7" ry="2.5" />
      <path d="M5 6v12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V6M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1" />
    </>
  ),
};

const ITEMS: { view: View; label: string; need?: Role }[] = [
  { view: "explore", label: "Explore" },
  { view: "filter", label: "Filter" },
  { view: "findings", label: "Findings" },
  { view: "remediation", label: "Remediation" },
  { view: "posture", label: "Posture" },
  { view: "zones", label: "Zones" },
  { view: "data", label: "Data" },
  { view: "reports", label: "Reports" },
  { view: "alerts", label: "Alerts", need: "analyst" },
];

const ADMIN_ITEMS: { id: string; label: string; icon: IconName }[] = [
  { id: "users", label: "Users", icon: "users" },
  { id: "sso", label: "SSO", icon: "sso" },
  { id: "collectors", label: "Collectors", icon: "collectors" },
  { id: "notifications", label: "Notifications", icon: "notifications" },
  { id: "audit", label: "Audit log", icon: "audit" },
  { id: "settings", label: "Server", icon: "server" },
];

function Icon({ name }: { name: IconName }) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" className="rail-icon">
      {ICONS[name]}
    </svg>
  );
}

/** Left navigation rail; views are hash links so they can be shared and bookmarked. */
export function NavRail({ route }: { route: Route }) {
  const { openSettings } = useApp();
  const { size } = useFixList();
  const { atLeast } = useSession();
  const current = route.view;
  return (
    <nav className="rail" aria-label="Views">
      {ITEMS.filter((i) => !i.need || atLeast(i.need)).map((i) => (
        <a key={i.view} href={routeHref(i.view)} className={`rail-item ${current === i.view ? "active" : ""}`} aria-current={current === i.view ? "page" : undefined}>
          <Icon name={i.view} />
          <span className="rail-label">{i.label}</span>
          {i.view === "remediation" && size > 0 && (
            <span className="rail-badge" aria-label={`${size} items in the fix list`}>
              {size}
            </span>
          )}
        </a>
      ))}
      {/* Admin pages are hidden for other roles; the server refuses them anyway. */}
      {atLeast("admin") && (
        <div className="rail-group" role="group" aria-label="Administration">
          <span className="rail-group-label">Admin</span>
          {ADMIN_ITEMS.map((i) => {
            const active = current === "admin" && (route.id ?? "users") === i.id;
            return (
              <a key={i.id} href={routeHref("admin", i.id)} className={`rail-item ${active ? "active" : ""}`} aria-current={active ? "page" : undefined}>
                <Icon name={i.icon} />
                <span className="rail-label">{i.label}</span>
              </a>
            );
          })}
        </div>
      )}
      <span className="spacer" />
      <button type="button" className="rail-item" onClick={() => openSettings("appearance")}>
        <Icon name="settings" />
        <span className="rail-label">Settings</span>
      </button>
    </nav>
  );
}
