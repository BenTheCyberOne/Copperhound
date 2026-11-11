import { EmptyState } from "../../components/StatusView";
import { useSession } from "../../state/SessionContext";
import { AuditView } from "./AuditView";
import { CollectorsView } from "./CollectorsView";
import { NotificationsView } from "./NotificationsView";
import { ServerSettingsView } from "./ServerSettingsView";
import { SsoView } from "./SsoView";
import { UsersView } from "./UsersView";

/** #/admin/users | #/admin/sso | #/admin/notifications?tab=… | #/admin/audit | #/admin/settings */
export function AdminView({ section, params }: { section: string | null; params: URLSearchParams }) {
  const { atLeast, role } = useSession();
  if (!atLeast("admin")) {
    return (
      <div className="view-page">
        <EmptyState title="Administrators only">
          This page needs the admin role; you are signed in as {role}. Ask an administrator if you need access.
        </EmptyState>
      </div>
    );
  }
  if (section === "audit") return <AuditView />;
  if (section === "settings") return <ServerSettingsView />;
  if (section === "sso") return <SsoView />;
  if (section === "collectors") return <CollectorsView />;
  if (section === "notifications") return <NotificationsView tab={params.get("tab")} />;
  return <UsersView />;
}
