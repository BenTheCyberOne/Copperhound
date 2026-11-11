import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { ChannelOut } from "../../api/types";
import { navigate } from "../../hooks/useRoute";
import { AlertRulesTab } from "./notify/AlertRulesTab";
import { ChannelsTab } from "./notify/ChannelsTab";
import { SchedulesTab } from "./notify/SchedulesTab";
import { TicketingTab } from "./notify/TicketingTab";

const TABS = [
  { id: "channels", label: "Channels" },
  { id: "schedules", label: "Scheduled reports" },
  { id: "alerts", label: "Alert rules" },
  { id: "ticketing", label: "Ticketing" },
] as const;
type Tab = (typeof TABS)[number]["id"];

/** #/admin/notifications?tab=channels|schedules|alerts|ticketing */
export function NotificationsView({ tab: rawTab }: { tab: string | null }) {
  const tab: Tab = TABS.some((t) => t.id === rawTab) ? (rawTab as Tab) : "channels";
  const [channels, setChannels] = useState<ChannelOut[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    api.channels().then(
      (r) => {
        setChannels(r.channels);
        setError(null);
      },
      (e: unknown) => setError(errorMessage(e)),
    );
  }, []);
  useEffect(reload, [reload]);

  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Notifications</h1>
          <p className="muted">
            Where CopperHound sends scheduled posture reports and change alerts (webhooks for SIEM / SOAR, Slack, Microsoft Teams,
            email) and remediation tickets (Jira, ServiceNow, webhooks).
          </p>
        </div>
      </header>
      <div className="tabs inline-tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? "active" : ""}
            onClick={() => navigate("admin", "notifications", { tab: t.id })}
          >
            {t.label}
          </button>
        ))}
      </div>
      {error && <p className="error">{error}</p>}
      {!channels && !error && <p className="muted">Loading…</p>}
      {channels && (
        <div role="tabpanel">
          {tab === "channels" && <ChannelsTab channels={channels} onChange={setChannels} />}
          {tab === "schedules" && <SchedulesTab channels={channels} />}
          {tab === "alerts" && <AlertRulesTab channels={channels} />}
          {tab === "ticketing" && <TicketingTab />}
        </div>
      )}
    </div>
  );
}
